# SSL Full Check and scripts 

What is needed? 

Ubuntu / Kali Distro 

```sudo apt search testssl```

Ubuntu : ``` sudo snap install testssl ```

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

https://www.youtube.com/watch?v=IHo-xQTbmos&ab_channel=HackTheMatrix