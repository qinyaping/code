#include <gtest/gtest.h>
#include "test1.h"

template<class T>
class FooTest : public testing::Test {
 public:
  static void SetUpTestCase() {
    shared_resource_ = new T();
  }
  static void TearDownTestCase() {
    if(shared_resource_) delete shared_resource_;
    shared_resource_ = NULL;
  }
  
  // Some expensive resource shared by all tests.
  static T* shared_resource_;
  static int num;
};
/*
范化定义可以在不同的（cpp）实现文件重复也可以赋予不同数值， 链接器负责选出唯一定义。
选择哪一个与具体的编译顺序有关。
因此，范化定义可以放在头文件中，具化定义放在唯一的cpp文件中
*/
//特定类型定义
template <> 
int FooTest<int/* any other type */>::num=2;
//通用类型定义
template<class T>
int FooTest<T>::num = 0;

template<>
Test1* FooTest<Test1>::shared_resource_ = NULL;

TEST(FooTest11, Test1)
{
	EXPECT_TRUE(FooTest<Test1>::shared_resource_->run());
		
}


//貌似TEST_F并不支持传递模板类进来
/*
TEST_F(FooTest<Test1>, Test1)
 {
    // you can refer to shared_resource here 
    EXPECT_TRUE(FooTest<Test1>::shared_resource_->run());
 }
TEST_F(FooTest<Test1>, Test2)
 {
    // you can refer to shared_resource here 
    EXPECT_TRUE(FooTest<Test1>::shared_resource_->run());
}
*/

/*
class FooCalcTest:public testing::Test
{
protected:
    virtual void SetUp()
    {
        m_foo.Init();
    }
    virtual void TearDown()
    {
        m_foo.Finalize();
    }

    FooCalc m_foo;
};

TEST_F(FooCalcTest, HandleNoneZeroInput)
{
    EXPECT_EQ(4, m_foo.Calc(12, 16));
}

TEST_F(FooCalcTest, HandleNoneZeroInput_Error)
{
    EXPECT_EQ(5, m_foo.Calc(12, 16));
}
*/

