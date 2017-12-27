/*
*   This test runs for one second
*/
#include <stdio.h>
#include <pthread.h>
#include <gcrypt.h>
#include <sys/time.h>

int count = 0;
char cmp_hash[32];
int time_sec = 1;

int main_hash()
{
    char *buffer = "hello";
    char digest[32];
    gcry_md_hash_buffer(GCRY_MD_SHA256, digest, buffer, 5);
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
    char *buffer = "hello";
    gcry_md_hash_buffer(GCRY_MD_SHA256, cmp_hash, buffer, 5);
    pthread_t tid1;//, tid2, tid3, tid4, tid5, tid6, tid7;
    pthread_create(&tid1, NULL, hash_cal, NULL);
    pthread_create(&tid1, NULL, hash_cal, NULL);
    pthread_create(&tid1, NULL, hash_cal, NULL);
    pthread_create(&tid1, NULL, hash_cal, NULL);
    pthread_create(&tid1, NULL, hash_cal, NULL);
    pthread_create(&tid1, NULL, hash_cal, NULL);
    pthread_create(&tid1, NULL, hash_cal, NULL);
    pthread_join(tid1, NULL);
    pthread_join(tid1, NULL);
    pthread_join(tid1, NULL);
    pthread_join(tid1,NULL);
    pthread_join(tid1, NULL);
    pthread_join(tid1, NULL);
    pthread_join(tid1, NULL);
    printf("Hashrate: %d Hashes in %ds\n", count,time_sec);
}
