#include "CryptoinoSHA256.h"

#define ROTLEFT(a,b) (((a) << (b)) | ((a) >> (32-(b))))
#define ROTRIGHT(a,b) (((a) >> (b)) | ((a) << (32-(b))))

#define CH(x,y,z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTRIGHT(x,2) ^ ROTRIGHT(x,13) ^ ROTRIGHT(x,22))
#define EP1(x) (ROTRIGHT(x,6) ^ ROTRIGHT(x,11) ^ ROTRIGHT(x,25))
#define SIG0(x) (ROTRIGHT(x,7) ^ ROTRIGHT(x,18) ^ ((x) >> 3))
#define SIG1(x) (ROTRIGHT(x,17) ^ ROTRIGHT(x,19) ^ ((x) >> 10))

SHA256::SHA256(){
	init();
}

void SHA256::init(){
	bytes = 0;
	
	buffer_index = 0;
	memcpy_P(state, SHA256_INIT_STATE, sizeof(SHA256_INIT_STATE));
}

size_t SHA256::write(uint8_t d){
	bytes++;
	addByte(d);
	return 1;
}

void SHA256::addByte(uint8_t d){
	data.b[buffer_index ^ 3] = d;
	buffer_index++;

	if(buffer_index == SHA256_BUFFERSIZE){
		hash_block();
		buffer_index = 0;
	}
}

void SHA256::hash_block(){
	uint8_t i;
	uint32_t a, b, c, d, e, f, g, h, t1, t2;
	
	a = state[0];
	b = state[1];
	c = state[2];
	d = state[3];
	e = state[4];
	f = state[5];
	g = state[6];
	h = state[7];

	for (i=0; i<64; i++) {
		if (i>=16) {
			t1 = data.w[i&15] + data.w[(i-7)&15];
			t2 = data.w[(i-2)&15];
			t1 += SIG1(t2);
			t2 = data.w[(i-15)&15];
			t1 += SIG0(t2);
			data.w[i&15] = t1;
		}
		
		t1 = h + EP1(e) + CH(e,f,g) + pgm_read_dword(SHA256_K + i) + data.w[i&15];
		t2 = EP0(a) + MAJ(a,b,c);
		h = g;
		g = f;
		f = e;
		e = d + t1;
		d = c;
		c = b;
		b = a;
		a = t1 + t2;
	}
	
	 state[0] += a;
	 state[1] += b;
	 state[2] += c;
	 state[3] += d;
	 state[4] += e;
	 state[5] += f;
	 state[6] += g;
	 state[7] += h;
}

void SHA256::pad(){
	addByte(0x80);
	while (buffer_index != 56) addByte(0);

	addByte(0);
	addByte(0);
	addByte(0);
	addByte(bytes >> 29);
	addByte(bytes >> 21);
	addByte(bytes >> 13);
	addByte(bytes >> 5);
	addByte(bytes << 3);
}

void SHA256::result(uint8_t hash[]){
	pad();

	for (int i=0; i<8; i++) {
		uint32_t a,b;
		a=state[i];
		b=a<<24;
		b|=(a<<8) & 0x00ff0000;
		b|=(a>>8) & 0x0000ff00;
		b|=a>>24;
		state[i]=b;
	}
	
	memcpy(hash, state, sizeof(state));
}
