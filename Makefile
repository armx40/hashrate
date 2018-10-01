default:
	cc main.c sha-2.c -lpthread -l gcrypt -Wall -o ./hashrate 
clean:
	rm ./hashrate