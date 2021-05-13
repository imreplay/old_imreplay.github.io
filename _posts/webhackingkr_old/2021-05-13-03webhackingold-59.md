---
title: "[Webhacking.kr(old)]-59"
excerpt: webhacking.kr old 59번 문제 풀이
categories:
  - wargame
tags: [webhacking.kr_old, web]
toc: false

---

문제 페이지에 접속하면 join, login창을 확인할 수 있다.

![/assets/img/webkrold59%20e7b54c8771c14a2f95c328ea7be6f3d5/Untitled.png](/assets/img/webkrold59%20e7b54c8771c14a2f95c328ea7be6f3d5/Untitled.png)

view-source를 눌러 소스를 확인한다.

```php
<?php
  include "../../config.php";
  if($_GET['view_source']) view_source();
  $db = dbconnect();
  if($_POST['lid'] && isset($_POST['lphone'])){
    $_POST['lid'] = addslashes($_POST['lid']);
    $_POST['lphone'] = addslashes($_POST['lphone']);
    $result = mysqli_fetch_array(mysqli_query($db,"select id,lv from chall59 where id='{$_POST['lid']}' and phone='{$_POST['lphone']}'"));
    if($result['id']){
      echo "id : {$result['id']}<br>lv : {$result['lv']}<br><br>";
      if($result['lv'] == "admin"){
      mysqli_query($db,"delete from chall59");
      solve(59);
    }
    echo "<br><a href=./?view_source=1>view-source</a>";
    exit();
    }
  }
  if($_POST['id'] && isset($_POST['phone'])){
    $_POST['id'] = addslashes($_POST['id']);
    $_POST['phone'] = addslashes($_POST['phone']);
    if(strlen($_POST['phone'])>=20) exit("Access Denied");
    if(preg_match("/admin/i",$_POST['id'])) exit("Access Denied");
    if(preg_match("/admin|0x|#|hex|char|ascii|ord|select/i",$_POST['phone'])) exit("Access Denied");
    mysqli_query($db,"insert into chall59 values('{$_POST['id']}',{$_POST['phone']},'guest')");
  }
?>
<html><head><title>Challenge 59</title></head><body>
<form method=post>
<table border=1>
<tr><td></td><td>ID</td><td>PHONE</td><td></td></tr>
<tr><td>JOIN</td><td><input name=id></td><td><input name=phone></td><td><input type=submit></td></tr>
<tr><td>LOGIN</td><td><input name=lid></td><td><input name=lphone></td><td><input type=submit></td></tr>
</form>
<br>
<a href=./?view_source=1>view-source</a>
</body></html>
```

join을 할 때, id의 값을 `nimda` (admin을 뒤집은 것) 으로 하고 phone 부분에 sql injection을 시도하였다, 이때 level의 값을 `admin`으로 주기 위하여 `reverse` 함수를 사용하여 admin을 만들어주었다.

가장 끝 부분에는 `--`  를 붙여주어 뒤의 구문을 주석처리하였다.

![/assets/img/webkrold59%20e7b54c8771c14a2f95c328ea7be6f3d5/Untitled%201.png](/assets/img/webkrold59%20e7b54c8771c14a2f95c328ea7be6f3d5/Untitled%201.png)

이후 가입했던 정보로 로그인을 진행한다.

![/assets/img/webkrold59%20e7b54c8771c14a2f95c328ea7be6f3d5/Untitled%202.png](/assets/img/webkrold59%20e7b54c8771c14a2f95c328ea7be6f3d5/Untitled%202.png)

성공적으로 admin의 권한을 얻어 문제 풀이를 완료할 수 있다.

![/assets/img/webkrold59%20e7b54c8771c14a2f95c328ea7be6f3d5/Untitled%203.png](/assets/img/webkrold59%20e7b54c8771c14a2f95c328ea7be6f3d5/Untitled%203.png)