//shared_ptr的简单实现版本  
//基于引用记数的智能指针  
//它可以和stl容器完美的配合  
namespace boost  
{  
	template<class T>  
		class shared_ptr  
		{  
			typedef unsigned long size_type;  
			private:  
			T *px;            // contained pointer  
			size_type* pn;    // reference counter  
			public:  
			//构造函数---------------------------------------------------2  
			/* 
			   int* a=new int(2); 
			   shared_ptr<int> sp; 
			   shared_ptr<int> sp(a); 
			 */  
			explicit shared_ptr(T* p=0) : px(p)  
			{  
				pn = new size_type(1);  
			}  

			/* 
			   Derived d; 
			   shared_ptr<Base> ap(d); 
			 */  
			template<typename Y>  
				shared_ptr(Y* py)  
				{  
					pn = new size_type(1);  
					px = py;  
				}  
			//copy构造函数------------------------------------------------  
			/* 
			   int * a=new int; 
			   shared_ptr<int> sp(a); 
			   shared_ptr<int> sp1(sp); 
			 */  
			shared_ptr(const shared_ptr& r) throw(): px(r.px)  
			{  
				++*r.pn;  
				pn = r.pn;  
			}  

			/* 
			   shared_ptr<Derived>sp1(derived); 
			   shared_ptr<Base> sp2(sp1); 
			 */  
			template<typename Y>  
				shared_ptr(const shared_ptr<Y>& r)//用于多态  
				{  
					px = r.px;  
					++*r.pn;  
					pn = r.pn; //shared_count::op= doesn't throw  
				}  
			//重载赋值operator=--------------------------------------------  
			shared_ptr& operator=(const shared_ptr& r) throw()  
			{  
				if(this== &r) return *this;  
				dispose();  
				px = r.px;  
				++*r.pn;  
				pn = r.pn;  
				return *this;  
			}  
			template<typename Y>  
				shared_ptr& operator=(const shared_ptr<Y>& r)//用于多态  
				{  
					dispose();  
					px = r.px;  
					++*r.pn;  
					pn = r.pn; //shared_count::op= doesn't throw  
					return *this;  
				}  

			~shared_ptr() { dispose(); }  
			void reset(T* p=0)  
			{  
				if ( px == p ) return;  
				if (--*pn == 0)  
				{ delete(px); }  
				else  
				{ // allocate newreference  
					// counter  
					// fix: prevent leak if new throws  
					try { pn = new size_type; }  
					catch (...) {  
						// undo effect of —*pn above to  
						// meet effects guarantee  
						++*pn;  
						delete(p);  
						throw;  
					} // catch  
				} // allocate newreference counter  
				*pn = 1;  
				px = p;  
			} // reset  
			reference operator*()const throw(){ return *px; }  
			pointer operator->()const throw(){ return px; }  
			pointer get() const throw(){ returnpx; }  
			size_type use_count() const throw()//  
			{ return *pn; }  
			bool unique() const throw()//  
			{ return *pn ==1; }  
			private:  
			void dispose() throw()  
			{  
				if (--*pn == 0)  
				{ delete px; delete pn; }  
			}  
		}; // shared_ptr  


	template<typename A,typename B>  
		inline bool operator==(shared_ptr<A>const & l, shared_ptr<B> const & r)  
		{  
			return l.get() == r.get();  
		}  
	template<typename A,typename B>  
		inline bool operator!=(shared_ptr<A>const & l, shared_ptr<B> const & r)  
		{  
			return l.get() != r.get();  
		}  
}//namespace boost  
