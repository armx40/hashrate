#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define WORD_SIZE 32
#define MESSAGE_BLOCK_SIZE 64

uint32_t constant[64] = {0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

/*void hex(uint8_t *s, uint8_t n)
{
    int j;
    printf("");
    for (j = 0; j < (n * 16); j++)
    {
        printf("%02X", s[j]);
    }
    printf("\n");
}
void hex_32(uint32_t *s, uint8_t n)
{
    int j;
    printf("");
    for (j = 0; j < (n * 16); j++)
    {
        printf("%08X", s[j]);
    }
    printf("\n");
}
*/
uint32_t ROTL(uint32_t x, uint8_t n)
{
    return (((x << n) | (x >> (WORD_SIZE - n))));
}
uint32_t ROTR(uint32_t x, uint8_t n)
{
    return (((x >> n) | (x << (WORD_SIZE - n))));
}
uint32_t SHR(uint32_t x, uint8_t n)
{
    return x >> n;
}

// FUNCTIONS

uint32_t ch(uint32_t x, uint32_t y, uint32_t z)
{
    return (x & y) ^ (~x & z);
}
uint32_t maj(uint32_t x, uint32_t y, uint32_t z)
{
    return (x & y) ^ (x & z) ^ (y & z);
}
uint32_t C_sigma_256_0(uint32_t x)
{
    return ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22);
}
uint32_t C_sigma_256_1(uint32_t x)
{
    return ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25);
}
uint32_t L_sigma_256_0(uint32_t x)
{
    return ROTR(x, 7) ^ ROTR(x, 18) ^ SHR(x, 3);
}
uint32_t L_sigma_256_1(uint32_t x)
{
    return ROTR(x, 17) ^ ROTR(x, 19) ^ SHR(x, 10);
}

void prepare_message_schedule(uint32_t *message_schedule, char *msg, uint8_t msg_len)
{
    uint8_t t;
    for (t = 0; t < 16; t++)
    {
        message_schedule[t] = (uint32_t)((uint8_t)msg[(4 * t) + 0] << 24) | (uint32_t)((uint8_t)msg[(4 * t) + 1] << 16) | (uint32_t)((uint8_t)msg[(4 * t) + 2] << 8) | (uint32_t)((uint8_t)msg[(4 * t) + 3] << 0);
    }
    for (t = 16; t < 64; t++)
    {
        message_schedule[t] = (L_sigma_256_1(message_schedule[t - 2]) + message_schedule[t - 7] + L_sigma_256_0(message_schedule[t - 15]) + message_schedule[t - 16]) % 0xffffffff;
    }
}
void sha_256(char *msg, uint64_t msg_len, char *digest_out)
{
    uint64_t l = msg_len * 8;
    int16_t k = 448 - (l + 1);
    int64_t out_size;
    if ((msg_len % MESSAGE_BLOCK_SIZE) < 56)
    {
        out_size = msg_len + (MESSAGE_BLOCK_SIZE - (msg_len % MESSAGE_BLOCK_SIZE));
    }
    else
    {
        out_size = msg_len + MESSAGE_BLOCK_SIZE + (MESSAGE_BLOCK_SIZE - (msg_len % MESSAGE_BLOCK_SIZE));
    }
    char out[out_size];
    memcpy(out, msg, msg_len);
    out[msg_len] = 0x80;
    memset(out + msg_len + 1, 0x00, out_size - msg_len - 8);
    out[out_size - 8] = (l >> 56) & 0xff;
    out[out_size - 7] = (l >> 48) & 0xff;
    out[out_size - 6] = (l >> 40) & 0xff;
    out[out_size - 5] = (l >> 32) & 0xff;
    out[out_size - 4] = (l >> 24) & 0xff;
    out[out_size - 3] = (l >> 16) & 0xff;
    out[out_size - 2] = (l >> 8) & 0xff;
    out[out_size - 1] = (l >> 0) & 0xff;

    uint32_t digest[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    uint32_t message_schedule[64];
    uint64_t N = (out_size) / MESSAGE_BLOCK_SIZE;
    uint8_t i;
    uint32_t a, b, c, d, e, f, g, h;
    for (i = 1; i <= N; i++)
    {
        prepare_message_schedule(message_schedule, out + ((i - 1) * 64), MESSAGE_BLOCK_SIZE);
        a = digest[0];
        b = digest[1];
        c = digest[2];
        d = digest[3];
        e = digest[4];
        f = digest[5];
        g = digest[6];
        h = digest[7];
        uint8_t t;
        for (t = 0; t < 64; t++)
        {
            uint32_t T_1 = (h + C_sigma_256_1(e) + ch(e, f, g) + constant[t] + message_schedule[t]) % 0xffffffff;
            uint32_t T_2 = (C_sigma_256_0(a) + maj(a, b, c)) % 0xffffffff;
            h = g;
            g = f;
            f = e;
            e = (d + T_1) % 0xffffffff;
            d = c;
            c = b;
            b = a;
            a = (T_1 + T_2) % 0xffffffff;
        }
        digest[0] = (a + digest[0]) % 0xffffffff;
        digest[1] = (b + digest[1]) % 0xffffffff;
        digest[2] = (c + digest[2]) % 0xffffffff;
        digest[3] = (d + digest[3]) % 0xffffffff;
        digest[4] = (e + digest[4]) % 0xffffffff;
        digest[5] = (f + digest[5]) % 0xffffffff;
        digest[6] = (g + digest[6]) % 0xffffffff;
        digest[7] = (h + digest[7]) % 0xffffffff;
    }
    //uint8_t k;
    for (k = 0; k < 8; k++)
    {
        digest_out[(k * 4) + 0] = (digest[k] >> 24) & 0xff;
        digest_out[(k * 4) + 1] = (digest[k] >> 16) & 0xff;
        digest_out[(k * 4) + 2] = (digest[k] >> 8) & 0xff;
        digest_out[(k * 4) + 3] = (digest[k] >> 0) & 0xff;
    }
}
