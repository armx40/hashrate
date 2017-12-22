default:
	cc main.c -lpthread -l gcrypt -Wall -o ./hashrate
clean:
	rm ./hashrate