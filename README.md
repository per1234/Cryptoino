Cryptoino
==============

## Description

An Arduino library implementing cryptographic algorithms.

Currently supports SHA256

## Example

```cpp
#include <Cryptoino.h>

SHA256 sha256;
uint8_t hash[SHA256_HASHSIZE];

void setup() {
  Serial.begin(9600);
}

void loop() {
  sha256.init();
  sha256.print("test");
  sha256.result(hash);
  
  for(int i =0; i < SHA256_HASHSIZE; i++){
    if(hash[i] < 0x10)
      Serial.print('0');
    Serial.print(hash[i], HEX);
  }
  Serial.println();
  
  delay(1000);
}

```


