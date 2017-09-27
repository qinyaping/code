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
������������ڲ�ͬ�ģ�cpp��ʵ���ļ��ظ�Ҳ���Ը��費ͬ��ֵ�� ����������ѡ��Ψһ���塣
ѡ����һ�������ı���˳���йء�
��ˣ�����������Է���ͷ�ļ��У��߻��������Ψһ��cpp�ļ���
*/
//�ض����Ͷ���
template <> 
int FooTest<int/* any other type */>::num=2;
//ͨ�����Ͷ���
template<class T>
int FooTest<T>::num = 0;

template<>
Test1* FooTest<Test1>::shared_resource_ = NULL;

TEST(FooTest11, Test1)
{
	EXPECT_TRUE(FooTest<Test1>::shared_resource_->run());
		
}


//ò��TEST_F����֧�ִ���ģ�������
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

