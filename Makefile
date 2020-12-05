all: airodump

airodump: main.cpp
	g++ -o airodump  main.cpp -lpcap -lncursesw

clean:
	rm -f airodump

