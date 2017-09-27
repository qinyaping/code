class TestCase
{
public:
    TestCase(const char* case_name) : testcase_name(case_name){}

    // ִ�в��԰����ķ���
    virtual void Run() = 0;

    int nTestResult; // ���԰�����ִ�н�� 
    
    const char* testcase_name; // ���԰�������
};


class UnitTest
{
public:
    // ��ȡ����
    static UnitTest* GetInstance(); 

    // ע����԰���
    TestCase* RegisterTestCase(TestCase* testcase);
    
    // ִ�е�Ԫ����
    int Run();

    TestCase* CurrentTestCase; 		// ��¼��ǰִ�еĲ��԰���
    int nTestResult; 				// �ܵ�ִ�н��
    int nPassed; 					// ͨ��������
    int nFailed; 					// ʧ�ܰ�����
protected:
    std::vector<TestCase*> testcases_; // ��������
};

