myserver:main.c network.c ssl.c epoll.c
	gcc main.c network.c ssl.c epoll.c -ldl -lcrypto `pkg-config --cflags --libs libssl` -o myserver -g -O0
clean:
	rm -rf myserver
