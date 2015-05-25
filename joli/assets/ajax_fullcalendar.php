<?php
/*
* Full calendar ajax load events example
* Like Pro admin template
* by Aqvatarius
*/

    $month  = date('m');
    $year   = date('Y');
    
    
    $data = array();
    $data[] = array('title'=>'Lorem ipsum dolor sit amet','start'=>$year.'-'.$month.'-01','className'=>'green');
    $data[] = array('title'=>'Donec eget ligula','start'=>$year.'-'.$month.'-03','className'=>'blue');
    $data[] = array('title'=>'Curabitur dapibus lectus','start'=>$year.'-'.$month.'-03','className'=>'red');
    $data[] = array('title'=>'Vivamus non','start'=>$year.'-'.$month.'-03','className'=>'orange');
    $data[] = array('title'=>'Duis sagittis','start'=>$year.'-'.$month.'-08');
    $data[] = array('title'=>'Nullam eget mauris','start'=>$year.'-'.$month.'-05','end'=>$year.'-'.$month.'-07','className'=>'red');    
    $data[] = array('title'=>'Proin laoreet justo nec','start'=>$year.'-'.$month.'-16','className'=>'orange');
    $data[] = array('title'=>'Ut faucibus sapien','start'=>date("Y-m-d"));
    $data[] = array('title'=>'Donec porta orci dapibus','start'=>$year.'-'.$month.'-21','end'=>$year.'-'.$month.'-28','className'=>'blue');
    $data[] = array('title'=>'Phasellus ac arcu in tortor faucibus pharetra','start'=>$year.'-'.$month.'-21','end'=>$year.'-'.$month.'-25','className'=>'red');
    
    echo json_encode($data);
?>