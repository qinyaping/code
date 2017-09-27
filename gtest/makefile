################################################################################################################  
#  
#           自动将当前目录及子目录下中的.cpp .cc文件编译，生成所有.o文件保存在bin/objs下  
#           修改TARGETS和CC以及CXXFLAGS和LDFLAG、LINKINC、LINKLIB、INCLUDE即可完成工程的配置  
#  
#################################################################################################################

#生成执行文件路径
PROJECT_BIN_DIR=bin

#包含头文件路径
PROJECT_INC_DIR=

#包含库文件路径
PROJECT_LIB_DIR=

#目标文件路径
PROJECT_OBJ_DIR=objs

#定义编译器
CC := g++

#生存目标文件
TARGETS = test

#编译参数
CXXFLAGS := -g -w -std=c++11

#链接参数
LDFLAG :=-lgtest -lrt -lpthread -ldl
#LDFLAG :=-lpthread -lrt -lboost_date_time -lboost_system -lboost_thread -ldl -Wl,-rpath /home/qinyp/study/boost/boost_install/lib

#链接库路径
LINKINC := -L$(PROJECT_LIB_DIR)/boost_install/lib

#链接库
LINKLIB :=#$(PROJECT_LIB_DIR)/boost_install/lib/libboost_thread.a $(PROJECT_LIB_DIR)/boost_install/lib/libboost_date_time.a $(PROJECT_LIB_DIR)/boost_install/lib/libboost_system.a

#包含目录路径
INCLUDE := -I $(PROJECT_INC_DIR)/boost_install/include

#递归遍历1级子目录
DIRS := $(shell find ./ -maxdepth 1 -type d)

#获取目录下的所有 .cpp .cc文件
#src :=$(wildcard $(dirs)/*.cpp)
SRC := $(foreach dir,$(DIRS),$(wildcard $(dir)/*.cpp $(dir)/*.cc))

#去除路径信息，只留文件名
DIR := $(notdir $(SRC))

#替换指定目录下的.cpp .cc文件为.o文件
PROJECT_OBJ := $(patsubst %.cpp,%.o,$(DIR))
PROJECT_OBJ := $(patsubst %.cc,%.o,$(PROJECT_OBJ))

#给指定文件添加前缀  即给文件名添加路径
PROJECT_ALL_OBJS := $(addprefix $(PROJECT_OBJ_DIR)/, $(PROJECT_OBJ))

#连接目标文件和依赖库 生成可执行文件
all:MKDIR $(PROJECT_ALL_OBJS)
	$(CC) $(LINKINC) $(PROJECT_ALL_OBJS)  $(LINKLIB) $(LDFLAG)  -o $(PROJECT_BIN_DIR)/$(TARGETS)
#	$(CC) $(LINKINC) $(PROJECT_ALL_OBJS) $(LINKLIB) $(LDFLAG) -o $(PROJECT_BIN_DIR)/$(TARGETS)

#创建目录
MKDIR:
	@mkdir -p $(PROJECT_OBJ_DIR)
	@mkdir -p $(PROJECT_BIN_DIR)

#根据源文件生成目标文件
#$(PROJECT_OBJ_DIR)/%.o : %.cpp
#	$(CC) -c $(CXXFLAGS) $(INCLUDE) $< -o $@

$(PROJECT_ALL_OBJS):$(SRC)
	$(CC) -c $(CXXFLAGS) $(INCLUDE) $(filter %$(*F).cpp %$(*F).cc,$(SRC)) -o $@

#清理目标文件
clean:  
	@rm -fr $(PROJECT_OBJ_DIR)
	@rm -fr $(PROJECT_BIN_DIR)

