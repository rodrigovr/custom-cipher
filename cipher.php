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
    private $pos = 0;

    public function CustomCipher($key) {
        $this->key = array_map('ord', str_split(hex2bin($key),1));
    }
    
    public function cipher($plaintext, $decoding = false)
    {
        $out = [];
        $size = count($this->key);
        
        foreach (unpack('C*', $plaintext) as $p) {
            // encode single byte
            $b = $p ^ $this->key[ $this->key[$this->pos] % $size ];
            // save
            $out[] = pack('C', $b);
            // modify key
            if ($decoding) {
                $this->key[$p % $size] ^= $b;
            } else {
                $this->key[$b % $size] ^= $p;
            }
            // rotate key usage
            $this->pos = ++$this->pos % $size; 
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