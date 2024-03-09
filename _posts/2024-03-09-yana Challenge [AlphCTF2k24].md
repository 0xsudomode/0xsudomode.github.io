---
title: yana Challenge Solution - AlphCTF2k24
date: 2023-11-27 04:23:00 
categories: [CTF]
tags: [android,reversing,apk,firebase,frida,AlphCTF2k24] 
---

# Info

AlphaCTF2k24 was held this week and there has been some amazing challenges out there . In this writeup we are going to solve the challenge called `yana` Note that the same technique could be used against `yana_revenge` which is the unintended solution. without further ado , let's begin.

# Challenge Description

![Figure](../../assets/img/posts/2/1.png)

We are presented with an android application , and the description is pretty straightforward ... it's a basic android app for note taking , which allows the user to write a public note as well as a private note which other users cannot see .

![](../../assets/img/posts/2/2.png)


The app use firebase internally , which hints for either an unauthorized access to the database or a misconfiguration which can allow us to manipulate the data somehow . 
If you look closely you'll notice that the first note is written by `ya.latreche@esi-sba.dz` and he mentioned that the flag is written in his private note . which means , in onder to get the flag we need somehow to takeover this user account and fetch his private notes .
  
# Tools Configuration

before we start we need to configure the necessary tools

## Burpsuite setup

To be able to proxy traffic through burp we need to configure it to listen to all interfaces , to be able to capture traffic from other devices on LAN

![](../../assets/img/posts/2/3.png)

## AVD setup

we need to configure the phone to use a proxy as well

![](../../assets/img/posts/2/4.png)

you need also to install burp certificate on the android device (Root is needed) if you visit http://burp on the android device the der file won't get recongnized .
to work around this issue , you can go to burpsuite , export the certificate and use openssl to convert it : `openssl x509 -inform der -in cacert.der -out cacert.pem`

![](../../assets/img/posts/2/5.png)

Copy the converted file to the phone storage and go to settings , search for the keyword certificates load cacert.pem and install it and we're done with configuring burp .

## Frida setup 

the installtion process for frida is pretty straightforward commands : 
install frida client : `pip3 install frida` 
install frida tools : `pip3 install frida-tools` 
then we need to download the correct frida-server that coresponds to the android emulator architecture from the official repo : https://github.com/frida/frida/releases in my case it is `frida-server-16.2.1-android-x86` since am using a x86 emulator . 
to determine the android emulator arch we can do it using ADB using the command : `adb shell getprop ro.product.cpu.abilist`


![](../../assets/img/posts/2/6.png)


If you're using android studio the virtual Device manager will display the info as automatically . next , we need to push `frida-server-16.2.1-android-x86` to the device using these commands respectively :

 ```
adb root 
adb push frida-server-16.2.1-android-x86 /data/local/tmp 
chmod +x frida-server-16.2.1-android-x86 
./frida-server-16.2.1-android-x86 
```

 you can get the package name using `frida-ps -U` , in this case it didn't work for for some reason so i had to use another tool , you can use any java decompiler to get the package name .
 in my case I will be using **GDA - Android reversing tool** , you can get it from the github repo on : https://github.com/charles2gan/GDA-android-reversing-Tool
In our case the package name is : **com.yalatreche.yana**

![](../../assets/img/posts/2/7.png)

# Solving the challenge 
Now while the frida server is listening , we need to bypass SSL pinning using a public script , we will run this command : 
`frida --codeshare akabe1/frida-multiple-unpinning -U -f com.yalatreche.yana`


![](../../assets/img/posts/2/8.png)

this will launch the app , hit the **register with google** button and we will be able to intercept the requests successfully with burpsuite as illustrated :

![](../../assets/img/posts/2/9.png)

Let's examine the response of the following request , from the action menu select do intercept **response to this request** now the response contains our email , that's interesting let's try to replace it with the email of the user holding the flag

![](../../assets/img/posts/2/10.png)
 
Nice , let's proceed with the second request which will be the a token sent in a post request , let's do the same and intercept the response of this request as well .

![](../../assets/img/posts/2/11.png)

This time the response contains more information of the current user let's change the email again to be **ya.latreche@esi-sba.dz**

![](../../assets/img/posts/2/12.png)
 
After doing this we will forward this request and close the application . then we need to change the proxy from **manual** to **none** and open the app manually this time , the session will still be valid and we will be able to take over the user's account successfully , now when opening the notes we will find the flag .

## Solution

![](../../assets/img/posts/2/13.png)

Flag : 
**AlphaCTF{y0U_317H3r_pR07ECt_y0uR_r0Ut35_0r_SecuR3_YOUR_f1R3b4sE_db}**

I would like to thank AlphCTF team members and event organizers for hosting such an amazing event . Also I want to thank yassine the creator for this challenge , He's an amazing guy.
