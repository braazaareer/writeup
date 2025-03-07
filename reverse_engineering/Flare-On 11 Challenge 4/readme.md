# Flare-On 11 Challenge 4 (FLARE Meme Maker 3000) [rev]
The challenge consisted of an HTML page embedding obfuscated JavaScript code. 
I used the online deobfuscation tool
[deobfuscate.relative.im](https://deobfuscate.relative.im/)
In the deobfuscated code, I encountered the following check:
```js
if (a !== Object.keys(a0e)[5]) {
    return;
}
```
This condition indicated that the variable a must match  index 5 of the object a0e
an array representing pictures.

Further down, the code validated three inputs using the array a0c:
```js
a0c.indexOf(b) == 14
a0c.indexOf(c) == a0c.length - 1
a0c.indexOf(d) == 22
```
By inspecting the contents of a0c, I identified the following values:

a0c[14] equals "FLARE On"
This value should be entered in the first text area (b).

a0c[25] equals "Security Expert"
This value should be entered in the second text area (c).

a0c[22] equals "Malware"
This value should be entered in the third text area (d).


## get flag
Select the picture at  5

Enter the following values in the respective text areas:
First text area: "FLARE On"
Second text area: "Security Expert"
Third text area: "Malware"

Once these conditions were satisfied, it will get flag 
