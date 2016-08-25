#!/usr/bin/env hhvm
<?php

/**
* CustomCipher is a stream cipher (!) that accepts a key of any length.
* The implementation is composed of 2 stages:
* - The first stage XORs the input byte with the next KEY byte
* - Then, the second stage modifies a single byte from the key
*/
class CustomCipher {

    private $key;

    public function CustomCipher($key) {
        $this->key = array_map('ord', str_split(hex2bin($key),1));
    }
    
    public function cipher($plaintext, $decoding = false)
    {
        $out = [];
        $pos = 0;
        $key = $this->key; // copy
        $size = count($key);
        
        foreach (unpack('C*', $plaintext) as $p) {
            // encode single byte
            $b = $p ^ $key[ $key[$pos] % $size ];
            // save
            $out[] = pack('C', $b);
            // modify key
            if ($decoding) {
                $key[$p % $size] ^= $b;
            } else {
                $key[$b % $size] ^= $p;
            }
            // rotate key usage
            $pos = ++$pos % $size; 
        }
        
        return join('',$out);
    }
}

$cipher = new CustomCipher($argv[1]);

$stdin = fopen('php://stdin','r');

$decode = isset($argv[2]) && $argv[2] == 'decode';

while (!feof($stdin)) {
    $plaintext = fread($stdin, 1024);
    echo $cipher->cipher($plaintext, $decode);
}