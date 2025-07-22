# Walkie Hackie
Rating: *Very Easy*

> Our agents got caught during a mission and found that the guards are using old walkie-talkies for their communication. The field team captured their transmissions. Can you interrupt their communication to help our agents escape from the guards?

I am given 4 files (`1.complex`, `2.complex`, `3.complex`, `4.complex`) and a this web interface: 

![](images/walkie_hackie_1.png)

Using [Universal Radio Hacker](https://github.com/jopohl/urh) I can analyze these `.complex` files.

Usually, you might see some encoding or some kind of redundancy thrown in to help with clock recovery and error correction. But here is nothing of that...this signal is just raw.
There’s a pattern at the start — a sync sequence to help the receiver lock onto the sender's clock.

Each signal starts with **preamble** ("aaaaaaaa") , then there is a **sync word** ("73214693") and then the **payload** ("a2ff84" or "a1ff14" or "b1ff57" or "b2ff24" for each `.complex` file). 

![](images/walkie_hackie_2.png)

Now to find the correct combination.

First I created the list for hex values and then I used the `ffuz` to do this.

`ffuf -w list_walkie_hackie:AA -w list_walkie_hackie:BB -u http://URL:PORT/transmit -d 'pa=aaaaaaaa&sw=73214693&pl=AAffBB' -H 'Content-Type: application/x-www-form-urlencoded'`

![](images/walkie_hackie_3.png)

... and then use any combination that returns response 200 in the web interface (or `curl` it).

# Mini Line
Rating: *Easy*

> The Investigation after a recent breach revealed that one of our standard firmware flashing tools is backdoored. We also identified the last device that we flashed the firmware onto. We use LPC2148 microcontrollers in our devices. Can you analyze the firmware and see if any data was sent?

Looking at the `.hex` extension I can find out it is Intel Hex used for:
> ... object file format, Intel hex format or Intellec Hex is a file format that conveys binary information in ASCII text form making it possible to store on non-binary media such as paper tape, punch cards, etc., to display on text terminals or be printed on line-oriented printers[*](https://en.wikipedia.org/wiki/Intel_HEX).

Then I used [hex2bin](https://github.com/algodesigner/hex2bin) to convert it to `.bin`.
After trying to execute this I found out it is an ARM binary.
I put the binary to [Dogbolt](https://dogbolt.org) to see if any decompiler would be successful with it (BinaryNinja was) and found:
```c

int32_t sub_5b4()
{
    int32_t var_24;
    __builtin_strncpy(&var_24, "RNXax.h)Ew)n.viE", 0x10);  /* ".3" */
    int32_t var_28 = 0xcc14961a;
    int32_t var_38 = 0xccae98be;
    int32_t var_34 = 0xbeba1214;
    int32_t var_30 = 0x30303010;
    char var_2c = 0x88;
    sub_4d0(sub_468("SPI Initialization"));
    sub_468("Start bit set");
    sub_520(1);  /* "lib/ld-linux.so.3" */
    sub_468("Transmitting data to slave");
    
    for (int32_t i = 0; i <= 0x10; i += 1)  /* "/lib/ld-linux.so.3" */  /* "lib/ld-linux.so.3" */
            /* ".3" */
        sub_520(*(&var_24 + i) ^ 0x1a);
    
    for (int32_t i_1 = 0; i_1 <= 4; i_1 += 1)  /* "/lib/ld-linux.so.3" */  /* "lib/ld-linux.so.3" */
            /* "/ld-linux.so.3" */
        sub_520(*(&var_28 + i_1) >> 1 ^ 0x39);  /* "lib/ld-linux.so.3" */
    
    for (int32_t i_2 = 0; i_2 <= 0xd; i_2 += 1)  /* "/lib/ld-linux.so.3" */  /* "lib/ld-linux.so.3"
            */  /* ".so.3" */
        sub_520(*(&var_38 + i_2) >> 1 ^ 0x39);  /* "lib/ld-linux.so.3" */
    
    sub_468("Data transfer is completed");
    sub_520(0);  /* "/lib/ld-linux.so.3" */
    return 0;  /* "/lib/ld-linux.so.3" */
}
```
... and there it is. The solution is just XOR each buffer with given number. 
