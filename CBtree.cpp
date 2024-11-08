#include <vector>
#include <array>
#include <string>
#include <utility>
#include <map>

using bytes=std::string;
// address profile = array [ PP | P | L | R | LL | LR | RL | RR ]

template<class addr_t> // addr_t = UDP/IP addr + port -> let be 8byte
class LinkProfile{
	std::array<addr_t,8> addr;
public:
	LinkProfile(){}
	LinkProfile(const bytes& dat){ // decode from bytes
		memcpy(&addr,&dat[0],sizeof addr);
	}
	bytes encode(){
		bytes dat(sizeof addr);
		memcpy(&dat[0],&addr,sizeof addr);
		return dat;
	}
};

template<class tcp_t,class addr_t>
class PeerTree{
	std::vector<std::pair<tcp_t,addr_t>> arr;
	std::map<tcp_t,int> addr_idx;
	LinkProfile<addr_t> extProfile(int i){
		LinkProfile<addr_t> p; // let 0.0.0.0 means nowhere 
		p[0]=arr[i/4].second;
		p[1]=arr[i/2].second;
		if(i*2<ssize(arr))p[2]=arr[i*2].second;
		if(i*2+1<ssize(arr))p[3]=arr[i*2+1].second;
		if(i*4<ssize(arr))p[4]=arr[i*4].second;
		if(i*4+1<ssize(arr))p[5]=arr[i*4+1].second;
		if(i*4+2<ssize(arr))p[6]=arr[i*4+2].second;
		if(i*4+3<ssize(arr))p[7]=arr[i*4+3].second;
		return p;
	}
public:
	PeerTree():arr(1){} // let [0] be data source ( central server )
	void init(tcp_t t,tcp_t u){
		arr[0]={t,u}; //arr[0] should never changes..?
		addr_idx[t]=0;
	}
	std::vector<std::pair<tcp_t,LinkProfile<addr_t>>> addPeer(tcp_t t,addr_t u){
		std::vector<std::pair<tcp_t,LinkProfile<addr_t>>> res;
		int i=ssize(arr);
		arr.emplace_back(t,u);
		addr_idx[t]=i;
		if(i/4)res.emplace_back(arr[i/4].first,extProfile(i/4)); // pp
		if(i/2)res.emplace_back(arr[i/2].first,extProfile(i/2)); // p
		res.emplace_back(arr[i].first,extProfile(i));
		return res;
	}
	std::vector<std::pair<tcp_t,LinkProfile<addr_t>>> deletePeer(int i){
		std::vector<std::pair<tcp_t,LinkProfile<addr_t>>> res;
		addr_idx.erase(arr[i].first);
		arr[i]=arr.back(); arr.pop_back();
		addr_idx[arr[i].first]=i;
		if(i/4)res.emplace_back(arr[i/4].first,extProfile(i/4)); // pp
		if(i/2)res.emplace_back(arr[i/2].first,extProfile(i/2)); // p
		res.emplace_back(arr[i].first,extProfile(i));
		if(i*2<ssize(arr))res.emplace_back(arr[i*2].first,extProfile(i*2));
		if(i*2+1<ssize(arr))res.emplace_back(arr[i*2+1].first,extProfile(i*2+1));
		if(i*4<ssize(arr))res.emplace_back(arr[i*4].first,extProfile(i*4));
		if(i*4+1<ssize(arr))res.emplace_back(arr[i*4+1].first,extProfile(i*4+1));
		if(i*4+2<ssize(arr))res.emplace_back(arr[i*4+2].first,extProfile(i*4+2));
		if(i*4+3<ssize(arr))res.emplace_back(arr[i*4+3].first,extProfile(i*4+3));
		int j=ssize(arr);
		if(j/4)res.emplace_back(arr[j/4].first,extProfile(j/4)); // pp
		if(j/2)res.emplace_back(arr[j/2].first,extProfile(j/2)); // p
		return res;
	}
};


int main(){
	PeerTree<int,int> V;
}
