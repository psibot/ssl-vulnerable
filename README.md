# SSL exploit checks and scripts 

What is needed? 

Ubuntu / Kali Distro 

```sudo apt search testssl```

Ubuntu : ``` sudo snap install testssl ```

Python3 : ``` pip3 install requests ```

If you need python3 packages use pip3 or pipx to install needed. 

## Some know issues

Some info , apple.com , facebook are still vurnerible to old ssl versions and exploits !!

### Example of facebook.com 

To check facebook.com run the following command 

```testssl  -U https://www.facebook.com/```

![FB](https://imgur.com/cFjxCSd.png)

### Example of apple.com 

To check apple.com run the following command 

``` testssl  -U https://www.apple.com/ ```

![APPLE](https://imgur.com/g1cS869.png)

Apple was owned in - 10 Oct 2024

![APPLE-BREACH](https://imgur.com/BUqSudB.png)

[Exploiting BREACH Attack (CVE-2013-3587) | How Apple.com Was Vulnerable](https://www.youtube.com/watch?v=IHo-xQTbmos&ab_channel=HackTheMatrix)


A example of this can be found here: 

```python3 apple-breach-poc.py ```

### But let us focus on facebook.com 

Facebook login portal 

https://www.facebook.com/login/ 

BREACH (CVE-2013-3587) 

```python3 breach-tester.py https://www.facebook.com/login/```

![FB-BREACH-BASIC](https://imgur.com/ETby5xH.png)

or 

```python3 breach-check1.py --verify  https://www.facebook.com/login/```

![FB-BREACH-EXTENDED](https://imgur.com/bwHvebu.png)

BEAST (CVE-2011-3389)

```python3 beast-tester.py --verify www.facebook.com```

![FB-BEAST](https://imgur.com/7XiuhT3.png)

