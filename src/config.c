struct socks5args * socks5_global_args;

struct socks5args * get_global_args(){
	return socks5_global_args;
}

void set_global_args(struct socks5args * args){
	socks5_global_args = args;
}