/*
*   This test runs for one second
*/

#define SHA2

#include <stdio.h>
#include <pthread.h>
#include <gcrypt.h>
#include <sys/time.h>
#include <stdint.h>
#include <inttypes.h>

#ifdef SHA2
    #include "sha-2.h"
#endif

uint64_t count = 0;
char cmp_hash[32];
char msg[] = {0xbf,0xf6,0x37,0x8b,0x73,0x37,0x48,0xa1,0xb9,0xc,0xaa,0x8c,0xd4,0x8f,0xd7,0x83,0xaf,0x83,0xf7,0xe6,0x23,0xe,0xee,0x17,0xf2,0x6d,0x6c,0x65,0x77,0x22,0x11,0xf,0xc1,0x4f,0x18,0x96,0x23,0xdb,0x8f,0x6c,0xb2,0x7a,0x7d,0xca,0x1c,0x6c,0x2c,0x3f,0xef,0xa,0x4b,0xcd,0x80,0x78,0x5f,0x7f,0xa2,0x9b,0x38,0xa,0xe9,0x85,0xc7,0x4a};
int time_sec = 5;

#define MSG_LEN 64
int main_hash()
{
    //char *buffer = "1213141516171819";
    char digest[32];
    //sha_256(buffer, 16, digest);
    #ifdef SHA2
        sha_256(msg,MSG_LEN,digest);
    #else
        gcry_md_hash_buffer(GCRY_MD_SHA256, digest, msg, MSG_LEN);
    #endif
    int a = memcmp(digest, cmp_hash, 32);
    if (!a)
    {
        count = count + 1;
    }
    return 0;
}

void *hash_cal()
{
    struct timeval tm;
    gettimeofday(&tm, NULL);
    int now = tm.tv_sec;

    // The following loop blocks until the second is almost an integer. This ensures that the test runs for correct amount of time.
    while ((tm.tv_sec - now) < 1)
    {
        gettimeofday(&tm, NULL);
    }
    // The test begins in this loop. Set time_sec to any value (in seconds).
    now = tm.tv_sec;
    while ((tm.tv_sec - now) < time_sec)
    {
        gettimeofday(&tm, NULL);
        main_hash();
    }
    return 0;
}

int main()
{
    //char *buffer = "1213141516171819";
    //sha_256(buffer, 16, cmp_hash);
    #ifdef SHA2
        sha_256(msg,MSG_LEN,cmp_hash);
    #else
        gcry_md_hash_buffer(GCRY_MD_SHA256, cmp_hash, msg, MSG_LEN);
    #endif
    pthread_t tid1, tid2, tid3; //,tid4;
    pthread_create(&tid1, NULL, hash_cal, NULL);
    pthread_create(&tid2, NULL, hash_cal, NULL);
    pthread_create(&tid3, NULL, hash_cal, NULL);
    //pthread_create(&tid4,NULL,hash_cal,NULL);
    pthread_join(tid1, NULL);
    pthread_join(tid2, NULL);
    pthread_join(tid3, NULL);
    //pthread_join(tid4,NULL);
    printf("hashrate: %" PRIu64, count);
    printf(" hashes in %ds\n", time_sec);
    return 0;
}
