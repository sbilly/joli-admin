CREATE OR REPLACE VIEW el_user_view AS
SELECT m.uid AS uid,
a1.value AS login,
a2.value AS pass,
a3.value AS f_name,
a4.value AS l_name,
a5.value AS s_name,
a6.value AS email,
a7.value AS phone_mobile,
a8.value AS phone_home,
a9.value AS city,
a10.value AS metro,
a11.value AS crtime,
a12.value AS mtime,
a13.value AS atime,
a14.value AS visits 
FROM el_user_profile_data AS m 
INNER JOIN el_user_profile_data AS a1 ON (m.uid=a1.uid AND a1.field=\'login\') 
INNER JOIN el_user_profile_data AS a2 ON (m.uid=a2.uid AND a2.field=\'pass\') 
INNER JOIN el_user_profile_data AS a3 ON (m.uid=a3.uid AND a3.field=\'f_name\') 
INNER JOIN el_user_profile_data AS a4 ON (m.uid=a4.uid AND a4.field=\'l_name\') 
INNER JOIN el_user_profile_data AS a5 ON (m.uid=a5.uid AND a5.field=\'s_name\') 
INNER JOIN el_user_profile_data AS a6 ON (m.uid=a6.uid AND a6.field=\'email\') 
INNER JOIN el_user_profile_data AS a7 ON (m.uid=a7.uid AND a7.field=\'phone_mobile\') 
INNER JOIN el_user_profile_data AS a8 ON (m.uid=a8.uid AND a8.field=\'phone_home\') 
INNER JOIN el_user_profile_data AS a9 ON (m.uid=a9.uid AND a9.field=\'city\') 
INNER JOIN el_user_profile_data AS a10 ON (m.uid=a10.uid AND a10.field=\'metro\') 
INNER JOIN el_user_profile_data AS a11 ON (m.uid=a11.uid AND a11.field=\'crtime\') 
INNER JOIN el_user_profile_data AS a12 ON (m.uid=a12.uid AND a12.field=\'mtime\') 
INNER JOIN el_user_profile_data AS a13 ON (m.uid=a13.uid AND a13.field=\'atime\') 
INNER JOIN el_user_profile_data AS a14 ON (m.uid=a14.uid AND a14.field=\'visits\') 
GROUP by m.uid

SELECT uid, MAX( IF( b =  \'login\', val, NULL ) ) login, MAX( IF( b =  \'email\', val, NULL ) ) email, MAX( IF( b =  \'f_name\', val, NULL ) ) f_name, MAX( IF( b =  \'mtime\', val, NULL ) ) mtime
FROM (

SELECT uid, field b, value val
FROM el_user_profile_data_test
) AS t
GROUP BY uid


Спасибо за подробный ответ.

1. На сколько я понимаю, приминимо к моей ситуации запрос будет выглядеть таким образом:
SELECT uid,
MAX(IF(field=\'login\',  value, NULL)) login,
MAX(IF(field=\'email\',  value, NULL)) email,
MAX(IF(field=\'f_name\', value, NULL)) f_name,
MAX(IF(field=\'mtime\',  value, NULL)) mtime
FROM el_user_profile_data_test
GROUP BY uid

Есть создать VIEW от этого запроса, то случайные выборки или объединения уже занимаю 6 секунд вместо 4, смущает что не используются идексы и explain говорит Using temporary; Using filesort. Будут ли вообще в такой ситуации индексы работать?

Почитав отзывы о VIEW в MySQL складывается мнение, что он ещё пока сыроват.


2. По поводу того что это религиозная война я полностью согласна, но одно дело работать с одним объектом данных или с 3мя и более (User, Address, Stats...), может есть ещё какой-то вариант оптимизировать скорость работы не разбивая структуры на отдельные сущности? Может ввести отдельную таблицу где будут храниться ID пользователей