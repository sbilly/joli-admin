#include "config.h"

#ifdef HAVE_SYS_CDEFS_H
#include <sys/cdefs.h>
#ifdef __RCSID  
__RCSID("$Id: milter-greylist.c,v 1.137.2.7 2006/11/07 05:12:11 manu Exp $");
#endif
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <syslog.h>
#include <ctype.h>
#include <time.h>
#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <grp.h>
#include <unistd.h>
#include <stdarg.h>

/* On IRIX, <unistd.h> defines a EX_OK that clashes with <sysexits.h> */
#ifdef EX_OK
#undef EX_OK
#endif
#include <sysexits.h>

#if HAVE_GETOPT_H
#include <getopt.h>
#endif

#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>

#ifdef USE_DRAC
#ifdef USE_DB185_EMULATION
#include <db_185.h>
#else
#include <db.h>
#endif
static int check_drac(char *dotted_ip);
#endif

#include <libmilter/mfapi.h>

#include "dump.h"
#include "acl.h"
#include "list.h"
#include "conf.h"
#include "pending.h"
#include "sync.h"
#include "spf.h"
#include "autowhite.h"
#include "milter-greylist.h"
#ifdef USE_DNSRBL
#include "dnsrbl.h"
#endif
#include "macro.h"

static char *gmtoffset(time_t *, char *, size_t);
static void writepid(char *);
static void log_and_report_greylisting(SMFICTX *, struct mlfi_priv *, char *);
static void reset_acl_values(struct mlfi_priv *);

struct smfiDesc smfilter =
{
	"greylist",	/* filter name */
	SMFI_VERSION,	/* version code */
	SMFIF_ADDHDRS,	/* flags */
	mlfi_connect,	/* connection info filter */
	MLFI_HELO,	/* SMTP HELO command filter */
	mlfi_envfrom,	/* envelope sender filter */
	mlfi_envrcpt,	/* envelope recipient filter */
	NULL,		/* header filter */
	NULL,		/* end of header */
	NULL,		/* body block filter */
	mlfi_eom,	/* end of message */
	NULL,		/* message aborted */
	mlfi_close,	/* connection cleanup */
};

sfsistat
mlfi_connect(ctx, hostname, addr)
	SMFICTX *ctx;
	char *hostname;
	_SOCK_ADDR *addr;
{
	struct mlfi_priv *priv;

	if ((priv = malloc(sizeof(*priv))) == NULL)
		return SMFIS_TEMPFAIL;	

	smfi_setpriv(ctx, priv);
	bzero((void *)priv, sizeof(*priv));
	priv->priv_whitelist = EXF_UNSET;

	strncpy(priv->priv_hostname, hostname, ADDRLEN);
	priv->priv_hostname[ADDRLEN] = '\0';

	if (addr != NULL) {
		switch (addr->sa_family) {
		case AF_INET:
			priv->priv_addrlen = sizeof(struct sockaddr_in);
			memcpy(&priv->priv_addr, addr, priv->priv_addrlen);
#ifdef HAVE_SA_LEN
			/* XXX: sendmail doesn't set sa_len */
			SA4(&priv->priv_addr)->sin_len = priv->priv_addrlen;
#endif
			break;
#ifdef AF_INET6
		case AF_INET6:
			priv->priv_addrlen = sizeof(struct sockaddr_in6);
			memcpy(&priv->priv_addr, addr, priv->priv_addrlen);
#ifdef SIN6_LEN
			/* XXX: sendmail doesn't set sa_len */
			SA6(&priv->priv_addr)->sin6_len = priv->priv_addrlen;
#endif
			unmappedaddr(SA(&priv->priv_addr),
			    &priv->priv_addrlen);
			break;
#endif
		default:
			priv->priv_elapsed = 0;
			priv->priv_whitelist = EXF_WHITELIST | EXF_NONIP;
			break;
		}
	} else {
		priv->priv_elapsed = 0;
		priv->priv_whitelist = EXF_WHITELIST | EXF_NONIP;
	}

	return SMFIS_CONTINUE;
}

sfsistat
mlfi_helo(ctx, helostr)
	SMFICTX *ctx;
	char *helostr;
{
	struct mlfi_priv *priv;

	priv = (struct mlfi_priv *) smfi_getpriv(ctx);

#if (defined(HAVE_SPF) || defined(HAVE_SPF_ALT) || \
     defined(HAVE_SPF2_10) || defined(HAVE_SPF2)) 
	strncpy_rmsp(priv->priv_helo, helostr, ADDRLEN);
	priv->priv_helo[ADDRLEN] = '\0';
#endif

	return SMFIS_CONTINUE;
}


sfsistat
mlfi_envfrom(ctx, envfrom)
	SMFICTX *ctx;
	char **envfrom;
{
	char tmpfrom[ADDRLEN + 1];
	char *idx;
	struct mlfi_priv *priv;
	char *auth_authen;
	char *verify;
	char *cert_subject;

	priv = (struct mlfi_priv *) smfi_getpriv(ctx);

	if ((priv->priv_queueid = smfi_getsymval(ctx, "{i}")) == NULL) {
		mg_log(LOG_DEBUG, "smfi_getsymval failed for {i}");
		priv->priv_queueid = "(unknown id)";
	}

	/*
	 * Strip spaces from the source address
	 */
	strncpy_rmsp(tmpfrom, *envfrom, ADDRLEN);
	tmpfrom[ADDRLEN] = '\0';

	/* 
	 * Strip anything before the last '=' in the
	 * source address. This avoid problems with
	 * mailing lists using a unique sender address
	 * for each retry.
	 */
	if ((idx = rindex(tmpfrom, '=')) == NULL)
		idx = tmpfrom;

	strncpy(priv->priv_from, idx, ADDRLEN);
	priv->priv_from[ADDRLEN] = '\0';

	/*
	 * Reload the config file if it has been touched
	 */
	conf_update();

	/*
	 * Is the sender non-IP?
	 */
	if (priv->priv_whitelist & EXF_NONIP)
		return SMFIS_CONTINUE;

	/*
	 * Is the user authenticated?
	 */
	if ((conf.c_noauth == 0) &&
	    ((auth_authen = smfi_getsymval(ctx, "{auth_authen}")) != NULL)) {
		mg_log(LOG_DEBUG, 
		    "User %s authenticated, bypassing greylisting", 
		    auth_authen);
		priv->priv_elapsed = 0;
		priv->priv_whitelist = EXF_WHITELIST | EXF_AUTH;

		return SMFIS_CONTINUE;
	} 

	/* 
	 * STARTTLS authentication?
	 */
	if ((conf.c_noauth == 0) &&
	    ((verify = smfi_getsymval(ctx, "{verify}")) != NULL) &&
	    (strcmp(verify, "OK") == 0) &&
	    ((cert_subject = smfi_getsymval(ctx, "{cert_subject}")) != NULL)) {
		mg_log(LOG_DEBUG, 
		    "STARTTLS succeeded for DN=\"%s\", bypassing greylisting", 
		    cert_subject);
		priv->priv_elapsed = 0;
		priv->priv_whitelist = EXF_WHITELIST | EXF_STARTTLS;

		return SMFIS_CONTINUE;
	}

	/*
	 * Is the sender address SPF-compliant?
	 */
	if ((conf.c_nospf == 0) && 
	    (SPF_CHECK(SA(&priv->priv_addr), priv->priv_addrlen,
	    priv->priv_helo, *envfrom) != EXF_NONE)) {
		char ipstr[IPADDRSTRLEN];

		if (iptostring(SA(&priv->priv_addr),
		    priv->priv_addrlen, ipstr, sizeof(ipstr))) {

			mg_log(LOG_DEBUG, 
			    "Sender IP %s and address %s are SPF-compliant, "
			    "bypassing greylist", ipstr, *envfrom);
		}

		priv->priv_elapsed = 0;
		priv->priv_whitelist = EXF_WHITELIST | EXF_SPF;

		return SMFIS_CONTINUE;
	}

	return SMFIS_CONTINUE;
}

sfsistat
mlfi_envrcpt(ctx, envrcpt)
	SMFICTX *ctx;
	char **envrcpt;
{
	struct mlfi_priv *priv;
	time_t remaining;
	char *greylist;
	char addrstr[IPADDRSTRLEN];
	char rcpt[ADDRLEN + 1];

	priv = (struct mlfi_priv *) smfi_getpriv(ctx);

	if (!iptostring(SA(&priv->priv_addr), priv->priv_addrlen, addrstr,
	    sizeof(addrstr)))
		return SMFIS_CONTINUE;

	if (conf.c_debug)
		mg_log(LOG_DEBUG, "%s: addr = %s[%s], from = %s, rcpt = %s", 
		    priv->priv_queueid, priv->priv_hostname, addrstr, priv->priv_from, *envrcpt);

	/*
	 * For multiple-recipients messages, if the sender IP or the
	 * sender e-mail address is whitelisted, authenticated, or
	 * SPF compliant, then there is no need to check again, 
	 * it is whitelisted for all the recipients.
	 * 
	 * Moreover, this will prevent a wrong X-Greylist header display
	 * if the {IP, sender e-mail} address was whitelisted and the
	 * last recipient was also whitelisted. If we would set priv_whitelist
	 * on the last recipient, all recipient would have a X-Greylist
	 * header explaining that they were whitelisted, whereas some
	 * of them would not.
	 */
	if ((priv->priv_whitelist & EXF_ADDR) ||
	    (priv->priv_whitelist & EXF_DOMAIN) ||
	    (priv->priv_whitelist & EXF_FROM) ||
	    (priv->priv_whitelist & EXF_AUTH) ||
	    (priv->priv_whitelist & EXF_SPF) ||
	    (priv->priv_whitelist & EXF_NONIP) ||
	    (priv->priv_whitelist & EXF_DRAC) ||
	    (priv->priv_whitelist & EXF_ACCESSDB) ||
	    (priv->priv_whitelist & EXF_MACRO) ||
	    (priv->priv_whitelist & EXF_STARTTLS))
		return SMFIS_CONTINUE;

#ifdef USE_DRAC
	if ((SA(&priv->priv_addr)->sa_family == AF_INET) && 
	    (conf.c_nodrac == 0) &&
	    check_drac(addrstr)) {
		mg_log(LOG_DEBUG, "whitelisted by DRAC");
		priv->priv_elapsed = 0;
		priv->priv_whitelist = EXF_DRAC;

		return SMFIS_CONTINUE;
	}
#endif

	 /*
	  * If sendmail rules have defined a ${greylist} macro
	  * with value WHITE, then it is whitelisted
	  */
	if ((conf.c_noaccessdb == 0) &&
	    ((greylist = smfi_getsymval(ctx, "{greylist}")) != NULL) &&
	    (strcmp(greylist, "WHITE") == 0)) {
		mg_log(LOG_DEBUG, 
		    "whitelisted by {greylist}");
		priv->priv_elapsed = 0;
		priv->priv_whitelist = EXF_ACCESSDB;
 
		return SMFIS_CONTINUE;
	}

	/* 
	 * Restart the sync master thread if nescessary
	 */
	sync_master_restart();

	/*
	 * Strip spaces from the recipient address
	 */
	strncpy_rmsp(rcpt, *envrcpt, ADDRLEN);
	rcpt[ADDRLEN] = '\0';

	/*
	 * Check the ACL
	 */
	reset_acl_values(priv);
	if ((priv->priv_whitelist = acl_filter(ctx, priv, rcpt)) & EXF_WHITELIST) {
		priv->priv_elapsed = 0;
		return SMFIS_CONTINUE;
	}

	/* 
	 * Blacklist overrides autowhitelisting...
	 */
	if (priv->priv_whitelist & EXF_BLACKLIST) {
		char aclstr[16];
		char *code = "551";
		char *ecode = "5.7.1";
		char *msg = "Go away!";

		if (priv->priv_acl_line != 0)
			snprintf(aclstr, sizeof(aclstr), " (ACL %d)", 
			    priv->priv_acl_line);

		mg_log(LOG_INFO, 
		    "%s: addr %s[%s] from %s to %s blacklisted%s",
		    priv->priv_queueid, priv->priv_hostname, addrstr, 
		    priv->priv_from, rcpt, aclstr);

		code = (priv->priv_code) ? priv->priv_code : code;
		ecode = (priv->priv_ecode) ? priv->priv_ecode : ecode;
		msg = (priv->priv_msg) ? priv->priv_msg : msg;
		(void)smfi_setreply(ctx, code, ecode, msg);

		return *code == '4' ? SMFIS_TEMPFAIL : SMFIS_REJECT;
	}

	/* 
	 * Check if the tuple {sender IP, sender e-mail, recipient e-mail}
	 * was autowhitelisted
	 */
	if ((priv->priv_whitelist = autowhite_check(SA(&priv->priv_addr),
	    priv->priv_addrlen, priv->priv_from, rcpt, priv->priv_queueid,
	    priv->priv_delay, priv->priv_autowhite)) != EXF_NONE) {
		priv->priv_elapsed = 0;
		return SMFIS_CONTINUE;
	}

	/*
	 * On a multi-recipient message, one message can be whitelisted,
	 * and the next ones be greylisted. The first one would
	 * pass through immediatly (priv->priv_delay = 0) with a 
	 * priv->priv_whitelist = EXF_NONE. This would cause improper
	 * X-Greylist header display in mlfi_eom()
	 *
	 * The fix: if we make it to mlfi_eom() with priv_elapsed = 0, this
	 * means that some recipients were whitelisted. 
	 * We can set priv_whitelist now, because if the message is greylisted
	 * for everyone, it will not go to mlfi_eom(), and priv_whitelist 
	 * will not be used.
	 */
	priv->priv_whitelist = EXF_WHITELIST | EXF_RCPT;

	/*
	 * Check if the tuple {sender IP, sender e-mail, recipient e-mail}
	 * is in the greylist and if it ca now be accepted. If it is not
	 * in the greylist, it will be added.
	 */
	if (pending_check(SA(&priv->priv_addr), priv->priv_addrlen,
	    priv->priv_from, rcpt, &remaining, &priv->priv_elapsed,
	    priv->priv_queueid, priv->priv_delay, priv->priv_autowhite) != 0)
		return SMFIS_CONTINUE;

	priv->priv_remaining = remaining;

	/*
	 * The message has been added to the greylist and will be delayed.
	 * If the sender address is null, this will be done after the DATA
	 * phase, otherwise immediately.
	 * Delayed reject with per-recipient delays or messages 
	 * will use the last match.
	 */
	if ((conf.c_delayedreject == 1) && 
	    (strcmp(priv->priv_from, "<>") == 0)) {
		priv->priv_delayed_reject = 1;
		if (*priv->priv_rcpt == 0)
			strcpy(priv->priv_rcpt, rcpt);
		else
			strcpy(priv->priv_rcpt, "(multiple recipients)");
		return SMFIS_CONTINUE;
	}

	/*
	 * Log temporary failure and report to the client.
	 */
	log_and_report_greylisting(ctx, priv, *envrcpt);
	return SMFIS_TEMPFAIL;
}

sfsistat
mlfi_eom(ctx)
	SMFICTX *ctx;
{
	struct mlfi_priv *priv;
	char hdr[HDRLEN + 1];
	int h, mn, s;
	char *fqdn = NULL;
	char *ip = NULL;
	char timestr[HDRLEN + 1];
	char tzstr[HDRLEN + 1];
	char tznamestr[HDRLEN + 1];
	char whystr [HDRLEN + 1];
	char host[ADDRLEN + 1];
	time_t t;
	struct tm ltm;

	priv = (struct mlfi_priv *) smfi_getpriv(ctx);

	if (priv->priv_delayed_reject) {
		log_and_report_greylisting(ctx, priv, priv->priv_rcpt);
		return SMFIS_TEMPFAIL;
	}

	if ((fqdn = smfi_getsymval(ctx, "{j}")) == NULL) {
		mg_log(LOG_DEBUG, "smfi_getsymval failed for {j}");
		gethostname(host, ADDRLEN);
		fqdn = host;
	}

	ip = smfi_getsymval(ctx, "{if_addr}");
#ifdef AF_INET6
	/*
	 * XXX: sendmail doesn't return {if_addr} when connection is
	 * from ::1
	 */
	if (ip == NULL && SA(&priv->priv_addr)->sa_family == AF_INET6) {
		char buf[IPADDRSTRLEN];

		if (iptostring(SA(&priv->priv_addr), priv->priv_addrlen, buf,
		    sizeof(buf)) != NULL &&
		    strcmp(buf, "::1") == 0)
			ip = "IPv6:::1";
	}
#endif
	if (ip == NULL) {
		mg_log(LOG_DEBUG, "smfi_getsymval failed for {if_addr}");
		ip = "0.0.0.0";
	}

	t = time(NULL);
	localtime_r(&t, &ltm);
	strftime(timestr, HDRLEN, "%a, %d %b %Y %T", &ltm);
	gmtoffset(&t, tzstr, HDRLEN);
	strftime(tznamestr, HDRLEN, "%Z", &ltm);

	if (priv->priv_elapsed == 0) {
		if ((conf.c_report & C_NODELAYS) == 0)
			return SMFIS_CONTINUE;
			
		whystr[0] = '\0';
		if (priv->priv_whitelist & EXF_DOMAIN) {
			ADD_REASON(whystr, "Sender DNS name whitelisted");
			priv->priv_whitelist &= ~EXF_DOMAIN;
		}
		if (priv->priv_whitelist & EXF_ADDR) {
			ADD_REASON(whystr, "Sender IP whitelisted");
			priv->priv_whitelist &= ~EXF_ADDR;
		}
		if (priv->priv_whitelist & EXF_FROM) {
			ADD_REASON(whystr, "Sender e-mail whitelisted");
			priv->priv_whitelist &= ~EXF_FROM;
		}
		if (priv->priv_whitelist & EXF_AUTH) {
			ADD_REASON(whystr, 
			    "Sender succeeded SMTP AUTH authentication");
			priv->priv_whitelist &= ~EXF_AUTH;
		}
		if (priv->priv_whitelist & EXF_ACCESSDB) {
			ADD_REASON(whystr, 
			    "Message whitelisted by Sendmail access database");
			priv->priv_whitelist &= ~EXF_ACCESSDB;
		}
		if (priv->priv_whitelist & EXF_DRAC) {
			ADD_REASON(whystr, 
			    "Message whitelisted by DRAC access database");
			priv->priv_whitelist &= ~EXF_DRAC;
		}
		if (priv->priv_whitelist & EXF_SPF) {
			ADD_REASON(whystr, "Sender is SPF-compliant");
			priv->priv_whitelist &= ~EXF_SPF;
		}
		if (priv->priv_whitelist & EXF_NONIP) {
#ifdef AF_INET6
			ADD_REASON(whystr, 
			    "Message not sent from an IPv4 neither IPv6 address");
#else
			ADD_REASON(whystr, 
			    "Message not sent from an IPv4 address");
#endif
			priv->priv_whitelist &= ~EXF_NONIP;
		}
		if (priv->priv_whitelist & EXF_STARTTLS) {
			ADD_REASON(whystr, "Sender succeeded STARTTLS authentication");
			priv->priv_whitelist &= ~EXF_STARTTLS;
		}
		if (priv->priv_whitelist & EXF_RCPT) {
			ADD_REASON(whystr, "Recipient e-mail whitelisted");
			priv->priv_whitelist &= ~EXF_RCPT;
		}
		if (priv->priv_whitelist & EXF_AUTO) {
			ADD_REASON(whystr, "IP, sender and recipient auto-whitelisted");
			priv->priv_whitelist &= ~EXF_AUTO;
		}
		if (priv->priv_whitelist & EXF_DNSRBL) {
			ADD_REASON(whystr, "Sender IP whitelisted by DNSRBL");
			priv->priv_whitelist &= ~EXF_DNSRBL;
		}
		if (priv->priv_whitelist & EXF_DEFAULT) {
			ADD_REASON(whystr, "Default is to whitelist mail");
			priv->priv_whitelist &= ~EXF_DEFAULT;
		}
		priv->priv_whitelist &= ~(EXF_GREYLIST | EXF_WHITELIST);
		if (priv->priv_whitelist != 0) {
			mg_log(LOG_ERR, "%s: unexpected priv_whitelist = %d",
			    priv->priv_queueid, priv->priv_whitelist);
			mystrlcat (whystr, "Internal error ", HDRLEN);
		}

		snprintf(hdr, HDRLEN, "%s, not delayed by "
		    "milter-greylist-%s (%s [%s]); %s %s (%s)",
		    whystr, PACKAGE_VERSION, fqdn, 
		    ip, timestr, tzstr, tznamestr);

		smfi_addheader(ctx, HEADERNAME, hdr);

		return SMFIS_CONTINUE;
	}

	h = priv->priv_elapsed / 3600;
	priv->priv_elapsed = priv->priv_elapsed % 3600;
	mn = (priv->priv_elapsed / 60);
	priv->priv_elapsed = priv->priv_elapsed % 60;
	s = priv->priv_elapsed;

	snprintf(hdr, HDRLEN,
	    "Delayed for %02d:%02d:%02d by milter-greylist-%s "
	    "(%s [%s]); %s %s (%s)", 
	    h, mn, s, PACKAGE_VERSION, fqdn, ip, timestr, tzstr, tznamestr);

	if (conf.c_report & C_DELAYS)
		smfi_addheader(ctx, HEADERNAME, hdr);

	return SMFIS_CONTINUE;
}

sfsistat
mlfi_close(ctx)
	SMFICTX *ctx;
{
	struct mlfi_priv *priv;

	if ((priv = (struct mlfi_priv *) smfi_getpriv(ctx)) != NULL) {
		if (priv->priv_code)
			free(priv->priv_code);
		if (priv->priv_ecode)
			free(priv->priv_ecode);
		if (priv->priv_msg)
			free(priv->priv_msg);
		free(priv);
		smfi_setpriv(ctx, NULL);
	}

	/*
	 * If we need to dump on each change and something changed, dump
	 */
	if ((dump_dirty != 0) && (conf.c_dumpfreq == 0))
		dump_flush();

	return SMFIS_CONTINUE;
}



int
main(argc, argv)
	int argc;
	char *argv[];
{
	int ch;
	int checkonly = 0;
	/*
	 * Load configuration defaults
	 */
	conf_defaults(&defconf);
	memcpy(&conf, &defconf, sizeof(conf));

	/* 
	 * Process command line options 
	 */
	while ((ch = getopt(argc, argv, "Aa:cvDd:qw:f:hp:P:Tu:rSL:M:l")) != -1) {
		switch (ch) {
		case 'A':
			defconf.c_noauth = 1;
			defconf.c_forced |= C_NOAUTH;
			break;

		case 'a':
			if (optarg == NULL) {
				mg_log(LOG_ERR, "%s: -a needs an argument",
				    argv[0]);
				usage(argv[0]);
			}
			defconf.c_autowhite_validity = 
			    (time_t)humanized_atoi(optarg);
			defconf.c_forced |= C_AUTOWHITE;
			break;
		case 'c':
		        checkonly = 1;
			break;

		case 'D':
			conf_nodetach = 1;
			defconf.c_forced |= C_NODETACH;
			break;

		case 'q':
			defconf.c_quiet = 1;
			defconf.c_forced |= C_QUIET;
			break;

		case 'r':
			mg_log(LOG_INFO, "milter-greylist-%s %s", 
			    PACKAGE_VERSION, BUILD_ENV);
			exit(EX_OK);
			break;

		case 'S':
			defconf.c_nospf = 1;
			defconf.c_forced |= C_NOSPF;
			break;

		case 'u': {
			if (geteuid() != 0) {
				mg_log(LOG_ERR, "%s: only root can use -u", 
				    argv[0]);
				exit(EX_USAGE);
			}

			if (optarg == NULL) {
				mg_log(LOG_ERR,
				    "%s: -u needs a valid user as argument",
				    argv[0]);
				usage(argv[0]);
			}
			defconf.c_user = optarg;
			defconf.c_forced |= C_USER;
			break;
		}
			
		case 'v':
			defconf.c_debug = 1;
			defconf.c_forced |= C_DEBUG;
			break;

		case 'w':
			if ((optarg == NULL) || 
			    ((defconf.c_delay = humanized_atoi(optarg)) == 0)) {
				mg_log(LOG_ERR,
				    "%s: -w needs a positive argument",
				    argv[0]);
				usage(argv[0]);
			}
			defconf.c_forced |= C_DELAY;
			break;

		case 'f':
			if (optarg == NULL) {
				mg_log(LOG_ERR, "%s: -f needs an argument",
				    argv[0]);
				usage(argv[0]);
			}
			conffile = optarg;
			break;

		case 'd':
			if (optarg == NULL) {
				mg_log(LOG_ERR, "%s: -d needs an argument",
				    argv[0]);
				usage(argv[0]);
			}
			defconf.c_dumpfile = optarg;
			defconf.c_forced |= C_DUMPFILE;
			break;
				
		case 'P':
			if (optarg == NULL) {
				mg_log(LOG_ERR, "%s: -P needs an argument",
				    argv[0]);
				usage(argv[0]);
			}
			defconf.c_pidfile = optarg;
			defconf.c_forced |= C_PIDFILE;
			break;

		case 'p':
			if (optarg == NULL) {
				mg_log(LOG_ERR, "%s: -p needs an argument",
				    argv[0]);
				usage(argv[0]);
			}
			defconf.c_socket = optarg;
			defconf.c_forced |= C_SOCKET;
			break;

		case 'L': {
			int cidr;
			char maskstr[IPADDRLEN + 1];

		  	if (optarg == NULL) {
				mg_log(LOG_ERR,
				    "%s: -L requires a CIDR mask", argv[0]);
				usage(argv[0]);
			}

			cidr = atoi(optarg);
			if ((cidr > 32) || (cidr < 0)) {
				mg_log(LOG_ERR,
				    "%s: -L requires a CIDR mask", argv[0]);
				usage(argv[0]);
			}
			prefix2mask4(cidr, &defconf.c_match_mask);
			defconf.c_forced |= C_MATCHMASK;

			if (defconf.c_debug)
				mg_log(LOG_DEBUG, "match mask: %s", 
				    inet_ntop(AF_INET, &defconf.c_match_mask, 
				    maskstr, IPADDRLEN));

			break;
		}

		case 'M': {
			int plen;
#ifdef AF_INET6
			char maskstr[INET6_ADDRSTRLEN + 1];
#endif

		  	if (optarg == NULL) {
				mg_log(LOG_ERR,
				    "%s: -M requires a prefix length",
				    argv[0]);
				usage(argv[0]);
			}

			plen = atoi(optarg);
			if ((plen > 128) || (plen < 0)) {
				mg_log(LOG_ERR,
				    "%s: -M requires a prefix length",
				    argv[0]);
				usage(argv[0]);
			}
#ifdef AF_INET6
			prefix2mask6(plen, &defconf.c_match_mask6);
			defconf.c_forced |= C_MATCHMASK6;

			if (defconf.c_debug)
				mg_log(LOG_DEBUG, "match mask: %s", 
				    inet_ntop(AF_INET6, &defconf.c_match_mask6,
				    maskstr, INET6_ADDRSTRLEN));

#endif
			break;
		}

		case 'T':
			defconf.c_testmode = 1;	
			defconf.c_forced |= C_TESTMODE;
			break;

		case 'l':
			defconf.c_acldebug = 1;
			defconf.c_forced |= C_ACLDEBUG;
			break;

		case 'h':
		default:
			usage(argv[0]);
			break;
		}
	}
	
	/*
	 * Various init
	 */
	conf_init();
	all_list_init();
	acl_init ();
	pending_init();
	peer_init();
	autowhite_init();
	dump_init();
#ifdef USE_DNSRBL
	dnsrbl_init();
#endif
	macro_init();

	/*
	 * Load config file
	 * We can do this without locking exceptlist, as
	 * normal operation has not started: no other thread
	 * can access the list yet.
	 */
	conf_load();

	if (checkonly) {
		mg_log(LOG_INFO, "config file \"%s\" is okay", conffile);
		exit(EX_OK);
	}

	openlog("milter-greylist", 0, LOG_MAIL);

	conf_cold = 0;

	if (conf.c_socket == NULL) {
		mg_log(LOG_ERR, "%s: No socket provided, exiting", argv[0]);
		usage(argv[0]);
	}
	cleanup_sock(conf.c_socket);
	(void)smfi_setconn(conf.c_socket);

	/*
	 * Reload a saved greylist
	 * No lock needed here either.
	 */
	dump_reload();

	/* 
	 * Register our callbacks 
	 */
	if (smfi_register(smfilter) == MI_FAILURE) {
		mg_log(LOG_ERR, "%s: smfi_register failed", argv[0]);
		exit(EX_UNAVAILABLE);
	}

	/*
	 * Turn into a daemon
	 */
	if (conf_nodetach == 0) {

		(void)close(0);
		(void)open("/dev/null", O_RDONLY, 0);
		(void)close(1);
		(void)open("/dev/null", O_WRONLY, 0);
		(void)close(2);
		(void)open("/dev/null", O_WRONLY, 0);

		if (chdir("/") != 0) {
			mg_log(LOG_ERR, "%s: cannot chdir to root: %s",
			    argv[0], strerror(errno));
			exit(EX_OSERR);
		}

		switch (fork()) {
		case -1:
			mg_log(LOG_ERR, "%s: cannot fork: %s",
			    argv[0], strerror(errno));
			exit(EX_OSERR);
			break;

		case 0:
			break;

		default:
			exit(EX_OK);	
			break;
		}

		if (setsid() == -1) {
			mg_log(LOG_ERR, "%s: setsid failed: %s",
			    argv[0], strerror(errno));
			exit(EX_OSERR);
		}
	}

	/* 
	 * Write down our PID to a file
	 */
	if (conf.c_pidfile != NULL)
		writepid(conf.c_pidfile);

	/*
	 * Drop root privs
	 */
	if (conf.c_user != NULL) {
		struct passwd *pw = NULL;

		if ((pw = getpwnam(conf.c_user)) == NULL) {
			mg_log(LOG_ERR, "%s: cannot get user %s data: %s",
			    argv[0], conf.c_user, strerror(errno));
			exit(EX_OSERR);
		}

#ifdef HAVE_INITGROUPS
		if (initgroups(conf.c_user, pw->pw_gid) != 0) {
		        mg_log(LOG_ERR, "%s: cannot change "
			    "supplementary groups: %s",
			    argv[0], strerror(errno));
			exit(EX_OSERR);
		}
#endif

		if (setgid(pw->pw_gid) != 0 ||
		    setegid(pw->pw_gid) != 0) {
			mg_log(LOG_ERR, "%s: cannot change GID: %s",
			    argv[0], strerror(errno));
			exit(EX_OSERR);
		}


		if ((setuid(pw->pw_uid) != 0) ||
		    (seteuid(pw->pw_uid) != 0)) {
			mg_log(LOG_ERR, "%s: cannot change UID: %s",
			    argv[0], strerror(errno));
			exit(EX_OSERR);
		}
	}

	/*
	 * Start the dumper thread
	 */
	dumper_start();

	/*
	 * Run the peer MX greylist sync threads
	 */
	sync_master_restart();
	sync_sender_start();

	/*
	 * Install an atexit() callback to perform
	 * a dump when milter-greylist exits.
	 */
	if (atexit(*final_dump) != 0) {
		mg_log(LOG_ERR, "atexit() failed: %s", strerror(errno));
		exit(EX_OSERR);
	}	

	/*
	 * Dump the ACL for debugging purposes
	 */
	if (conf.c_debug || conf.c_acldebug)
		acl_dump();

	/*
	 * Here we go!
	 */
	return smfi_main();
}

void
usage(progname)
	char *progname;
{
	mg_log(LOG_ERR,
	    "usage: %s [-A] [-a autowhite_delay] [-c] [-D] [-d dumpfile]",
	    progname);
	mg_log(LOG_ERR,
	    "       [-f configfile] [-h] [-l] [-q] [-r] [-S] [-T]");
	mg_log(LOG_ERR,
	    "       [-u username] [-v] [-w greylist_delay] [-L cidrmask]");
	mg_log(LOG_ERR,
	    "       [-M prefixlen] [-P pidfile] -p socket");
	exit(EX_USAGE);
}

void
cleanup_sock(path)
	char *path;
{
	struct stat st;

	/* Does it exists? Get information on it if it does */
	if (stat(path, &st) != 0)
		return;

	/* Is it a socket? */
	if ((st.st_mode & S_IFSOCK) == 0)
		return;

	/* Remove the beast */
	(void)unlink(path);
	return;
}

char *
strncpy_rmsp(dst, src, len)
	char *dst;
	char *src;
	size_t len;
{
	unsigned int i;

	for (i = 0; src[i] && (i < len); i++) {
		if (isgraph((int)(unsigned char)src[i]))
			dst[i] = src[i];
		else
			dst[i] = '_';
	}

	if (i < len)
		dst[i] = '\0';

	return dst;
}

int
humanized_atoi(str)	/* *str is modified */
	char *str;
{
	unsigned int unit;
	size_t len;
	char numstr[NUMLEN + 1];

	if (((len = strlen(str)) || (len > NUMLEN)) == 0)
		return 0;

	switch(str[len - 1]) {
	case 's':
		unit = 1;
		break;

	case 'm':
		unit = 60;
		break;

	case 'h':
		unit = 60 * 60;
		break;

	case 'd':
		unit = 24 * 60 * 60;
		break;

	case 'w':
		unit = 7 * 24 * 60 * 60;
		break;

	default:
		return atoi(str);
		break;
	}

	strncpy(numstr, str, NUMLEN);
	numstr[len - 1] = '\0';

	return (atoi(numstr) * unit);
}

static char *
gmtoffset(date, buf, size)
	time_t *date;
	char *buf;
	size_t size;
{
	struct tm gmt;
	struct tm local;
	int offset;
	char *sign;
	int h, mn;

	gmtime_r(date, &gmt);
	localtime_r(date, &local);

	offset = local.tm_min - gmt.tm_min;
	offset += (local.tm_hour - gmt.tm_hour) * 60;

	/* Offset cannot be greater than a day */
	if (local.tm_year <  gmt.tm_year)
		offset -= 24 * 60;
	else
		offset += (local.tm_yday - gmt.tm_yday) * 60 * 24;

	if (offset >= 0) {
		sign = "+";
	} else {
		sign = "-";
		offset = -offset;
	}
	 
	h = offset / 60;
	mn = offset % 60;

	snprintf(buf, size, "%s%02d%02d", sign, h, mn);
	return buf;
}

static void
writepid(pidfile)
	char *pidfile;
{
	FILE *stream;

	if ((stream = fopen(pidfile, "w")) == NULL) {
		mg_log(LOG_ERR, "Cannot open pidfile \"%s\" for writing: %s", 
		    pidfile, strerror(errno));
		return;
	}

	fprintf(stream, "%ld\n", (long)getpid());
	fclose(stream);

	return;
}


struct in_addr *
prefix2mask4(cidr, mask)
	int cidr;
	struct in_addr *mask;
{

	if ((cidr == 0) || (cidr > 32)) {
		bzero((void *)mask, sizeof(*mask));
	} else {
		cidr = 32 - cidr;
		mask->s_addr = htonl(~((1UL << cidr) - 1));
	}
	
	return mask;
}

#ifdef AF_INET6
struct in6_addr *
prefix2mask6(plen, mask)
	int plen;
	struct in6_addr *mask;
{
	int i;
	uint32_t m;

	if (plen == 0 || plen > 128)
		bzero((void *)mask, sizeof(*mask));
	else {
		for (i = 0; i < 16; i += 4) {
			if (plen < 32)
				m = ~(0xffffffff >> plen);
			else
				m = 0xffffffff;
			*(uint32_t *)&mask->s6_addr[i] = htonl(m);
			plen -= 32;
			if (plen < 0)
				plen = 0;
		}
	}

	return mask;
}
#endif

void
unmappedaddr(sa, salen)
	struct sockaddr *sa;
	socklen_t *salen;
{
#ifdef AF_INET6
	struct in_addr addr4;
	int port;       
			
	if (SA6(sa)->sin6_family != AF_INET6 ||
	    !IN6_IS_ADDR_V4MAPPED(SADDR6(sa)))
		return;
	addr4.s_addr = *(uint32_t *)&SADDR6(sa)->s6_addr[12];
	port = SA6(sa)->sin6_port;
	bzero(sa, sizeof(struct sockaddr_in));
	SADDR4(sa)->s_addr = addr4.s_addr;
	SA4(sa)->sin_port = port;
	SA4(sa)->sin_family = AF_INET;
#ifdef HAVE_SA_LEN
	SA4(sa)->sin_len = sizeof(struct sockaddr_in);
#endif
	*salen = sizeof(struct sockaddr_in);
#endif
	return;
}

void
log_and_report_greylisting(ctx, priv, rcpt)
	SMFICTX *ctx;
	struct mlfi_priv *priv;
	char *rcpt;
{
	int h, mn, s;
	char hdr[HDRLEN + 1];
	char addrstr[IPADDRSTRLEN];
	time_t remaining;
	char *delayed_rj;
	char aclstr[16];
	char *code = "451";
	char *ecode = "4.7.1";
	char *msg = "Greylisting in action, please come back later";

	/*
	 * The message has been added to the greylist and will be delayed.
	 * Log this and report to the client.
	 */
	iptostring(SA(&priv->priv_addr), priv->priv_addrlen, addrstr,
	    sizeof(addrstr));

	remaining = priv->priv_remaining;
	h = remaining / 3600;
	remaining = remaining % 3600;
	mn = (remaining / 60);
	remaining = remaining % 60;
	s = remaining;

	if (priv->priv_delayed_reject)
		delayed_rj = " after DATA phase";
	else
		delayed_rj = "";

	if (priv->priv_acl_line != 0)
		snprintf(aclstr, sizeof(aclstr), " (ACL %d)", 
		    priv->priv_acl_line);
	else
		aclstr[0] = '\0';

	mg_log(LOG_INFO, 
	    "%s: addr %s[%s] from %s to %s delayed%s for %02d:%02d:%02d%s",
	    priv->priv_queueid, priv->priv_hostname, addrstr, 
	    priv->priv_from, rcpt, delayed_rj, h, mn, s, aclstr);

	code = (priv->priv_code) ? priv->priv_code : code;
	ecode = (priv->priv_ecode) ? priv->priv_ecode : ecode;

	if (conf.c_quiet) {
		msg = (priv->priv_msg) ? priv->priv_msg : msg;
	} else {
		snprintf(hdr, HDRLEN,
		    "Greylisting in action, please come "
		    "back in %02d:%02d:%02d", h, mn, s);
		msg = (priv->priv_msg) ? priv->priv_msg : hdr;
	}

	(void)smfi_setreply(ctx, code, ecode, msg);

	return;
}

void
final_dump(void) {

	if (dump_dirty != 0) {
		mg_log(LOG_INFO, "Final database dump");
		dump_perform();
	} else {
		mg_log(LOG_INFO, "Final database dump: no change to dump");
	}

	mg_log(LOG_INFO, "Exiting");
	return;
}

#ifdef	USE_DRAC
static int
check_drac(dotted_ip)
	char *dotted_ip;
{
	DB *ddb;
	DBT key, data;
	char ipkey[16];
	int rc;

	ddb = dbopen(conf.c_dracdb, O_RDONLY | O_SHLOCK, 0666, DB_BTREE, NULL);
	if (ddb == NULL) {
		mg_log(LOG_DEBUG, "dbopen \"%s\" failed", conf.c_dracdb);
		return 0;
	}

	key.data = strncpy(ipkey, dotted_ip, sizeof(ipkey));
	key.size = strlen(ipkey);
	rc = ddb->get(ddb, &key, &data, 0);
	ddb->close(ddb);

	switch (rc) {
	case 0:
#ifdef TEST
		mg_log(LOG_DEBUG, "key.data=%.*s (len=%d) "
		    "data.data=%.*s (len=%d)",
		    key.size, key.data, key.size,
		    data.size, data.data, data.size);
#endif /* TEST */
		return 1;
		break;

	case 1:
		return 0;
		break;

	default:
		mg_log(LOG_ERR, "check_drack: errno=%d", errno);
		break;
	}

	return 0;
}
#endif	/* USE_DRAC */

static void 
reset_acl_values(priv)
	struct mlfi_priv *priv;
{
	priv->priv_delay = conf.c_delay;
	priv->priv_autowhite = conf.c_autowhite_validity;

	if (priv->priv_code != NULL) {
		free(priv->priv_code);
		priv->priv_code = NULL;
	}
	if (priv->priv_ecode != NULL) {
		free(priv->priv_ecode);
		priv->priv_ecode = NULL;
	}
	if (priv->priv_msg != NULL) {
		free(priv->priv_msg);
		priv->priv_msg = NULL;
	}

	return;
}


#ifndef HAVE_STRLCAT
size_t
mystrlcat(dst, src, len)
	char *dst;
	const char *src;
	size_t len;
{
	size_t srclen = strlen(src);
	size_t dstlen;

	for (dstlen = 0; dstlen != len && dst[dstlen]; ++dstlen)
		;
	if (dstlen == len) {
#if 0
		/* BSD's strlcat leaves the string not NUL-terminated. */
		return dstlen + srclen;
#else
		/* This situation is a bug. We make core dump. */
		abort();
#endif
	}
	strncpy(dst + dstlen, src, len - dstlen - 1);
	dst[len - 1] = '\0';
	return dstlen + srclen;
}
#endif

#ifndef HAVE_VSYSLOG
#ifndef LINE_MAX
#define LINE_MAX 1024
#endif /* LINE_MAX */
void
vsyslog(level, fmt, ap)
	int level;
	char *fmt;
	va_list ap;
{
	char messagebuf[LINE_MAX];

	vsnprintf(messagebuf, sizeof(messagebuf), fmt, ap);
	messagebuf[sizeof(messagebuf) - 1] = '\0';
	syslog(level, "%s", messagebuf);

	return;
}
#endif /* HAVE_VSYSLOG */

/* VARARGS */
void
mg_log(int level, char *fmt, ...) {
	va_list ap;

	va_start(ap, fmt);

	if (conf_cold || conf_nodetach) {
		vfprintf(stderr, fmt, ap);
		fprintf(stderr, "\n");
	}

	if (!conf_cold)
		vsyslog(level, fmt, ap);

	va_end(ap);
	return;
}
