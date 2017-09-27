#include <iostream>

using namespace std;

class father{
		public:
				father(int i){cout<<__FUNCTION__<<endl;}

				virtual void func1(){cout<<__FUNCTION__<<endl;}
                void test_son(){cout<<__FUNCTION__<<endl;}
};

class mother{
        public:
                mother(){cout<<__FUNCTION__<<endl;}
};

class brother{
        public:
            brother(){cout<<__FUNCTION__<<endl;}
            brother(const brother& r){a = r.a; cout<<"brother::copy construct"<<endl;}

            int a; 
};

brother r;
class son : public father, public mother{
	public:
			//son():father(1),bro(r) {cout<<__FUNCTION__<<endl;}
			son():father(1) {cout<<__FUNCTION__<<endl;}

			void func1(){cout<<"son: "<<__FUNCTION__<<endl;}

			void func2(){cout<<__FUNCTION__<<endl;}
    private:
            brother bro;
};
int main()
{
		father* f = new son();

//		f->func1();
//        son so;
//        std::bind(&son::test_son(), f);
//f->func2();
		return 0;
}
