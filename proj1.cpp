#include "pin.H"
#include <vector>
#include<iostream>
#include<string.h>
#include <asm/unistd.h>
 #include <stdint.h>
#include <fstream>
#include <vector>
#define MAIN "main"
#define FILENO "fileno"
//using namespace std;


// Taint the memory if the source of input is stdin
#define FGETS "fgets"
#define GETS "gets"

// Propagate if the src is tainted
#define STRCPY "strcpy@plt"
#define STRNCPY "strncpy@plt"
#define STRCAT "strcat@plt"
#define STRNCAT "strncat@plt"
#define MEMCPY "memcpy@plt"

// Reset tainted memory
#define BZERO "bzero@plt"
#define MEMSET "memset@plt"
#define STRING_COPY "string_copy"
#define MYSTRCPY "mystrcpy"

struct taintedData {
        string address;
        int size;
        string funcaddr;
    string stacktrace;
}t;
struct taintedReg {
    string address;
    int size;
    string funcaddr;
    string stacktrace;
}r;
string mainaddress;
vector<taintedData> table;
vector<string>stackdata;
vector<taintedReg> regis;
typedef int ( *FP_FILENO )(FILE*);
FP_FILENO org_fileno;
int counter=0;
void printTable()
{
        size_t siz=table.size();
        printf("\nSIZE OF TABLE %d",siz);
        vector<taintedData>::iterator t;
        cout<<" \nIn table";
        cout<<"\nAddr : \t\tSize Range : \t\n";
        for(t=table.begin();t!=table.end();++t){
    cout<<t->address<<"\t"<<t->size<<"\t"<<t->funcaddr<<"\t"<<t->stacktrace<<"\n";
        }
}
void printTaint(char *addr, int len){
    for(int i = 0; i<len; i++){
        char address[25];
        sprintf(address,"%p",addr+i);
        cout<<"\n[TAINTBYTE]: "<<address;
}
}
void printTaint(char *dest, char* src, int len){
    for(int i = 0; i<len; i++){
        char destaddr[25];
        sprintf(destaddr,"%p",dest+i);
        char srcaddr[25];
        sprintf(srcaddr,"%p",src+i);
        cout<<"\n[TAINTBYTE]: "<<srcaddr;
        cout<<"\n[PROPAGATEBYTE]: "<<srcaddr<<" -> "<<destaddr;
}
}
void printvector(){
    vector<string>::iterator t;
    cout<<"\n";
    for(t=stackdata.begin();t!=stackdata.end();++t){
        cout<<"\t"<<*t;
    }
}

bool checktable(char *src){

        char srcaddr[25];
        sprintf(srcaddr,"%p",src);
        char finaladdr[25];
        int len=strlen(src)-1;
        sprintf(finaladdr,"%p",src+len);

        size_t siz=table.size();

        for(size_t i = 0; i<siz; i++) {
                if(srcaddr >= table[i].address && srcaddr <= finaladdr ){

                        return true;
                }
        }
        return false;
}

int check_stack(char *addr){
    
    char destaddr[25];
    sprintf(destaddr,"%s",addr);
    size_t siz=table.size();
    for(size_t i = 0; i<siz; i++) {
        if(destaddr==table[i].funcaddr) {
            return 1;
        }
}
    return 0;
   
}
/*int checkreturn(ADDRINT addr){
    char ret[25];
    sprintf(ret,"%x",addr);
    size_t siz=table.size();
    for(size_t i = 0; i<siz; i++) {
        if(ret==table[i].retaddr) {
            return 1;
        }
    }
    return 0;
    
}*/

void markDataTainted(char *dest, int len,ADDRINT inst, string stack){
        char addr[25];
        sprintf(addr,"%p",dest);
        char instr[25];
        sprintf(instr,"0x%x",inst);
    //char *c=const_cast<char *>(addr1.c_str());
   
        t.address=addr;
        t.size=len;
        t.funcaddr=instr;
    t.stacktrace=stack;
        table.push_back(t);
}
void catDataTainted(char *dest,int len, ADDRINT inst){
        bool exist=checktable(dest);
        char addr[25];
        sprintf(addr,"%p",dest);
    char instr[25];
    sprintf(instr,"%x",inst);
        char finaladdr[25];
        int destlen=strlen(dest)-1;
        sprintf(finaladdr,"%p",dest+destlen);
        if(exist)
        {
                for(size_t i = 0; i<table.size(); i++) {
                        if(addr==table[i].address){
                                table[i].size+=len;

                        }
                        else if(addr >= table[i].address && addr <=finaladdr ){
                                table[i].size+=len;
                        }
                }
        }
        else if(!exist){
                t.address=addr;
                t.size=len;
                t.funcaddr=instr;
                table.push_back(t);
        }

}
void markDataTainted(char *dest,char *src,int len,ADDRINT inst,string stack){
        bool exist=checktable(src);
        char addr1[25];
        sprintf(addr1,"%p",dest);
    char instr[25];
    sprintf(instr,"0x%x",inst);
   
    //char *c=const_cast<char *>(addr1.c_str());
    
        if(exist)
        {
                t.address=addr1;
                t.size=len;
            t.funcaddr=instr;
            t.stacktrace=stack;
                table.push_back(t);
        }
    printTaint(dest,src,len);
    //addstacktrace(addr1);
}
void adddata(char *src,int len,ADDRINT inst){
    char addr1[25];
    sprintf(addr1,"%p",src);
    char instr[25];
    sprintf(instr,"0x%x",inst);
    
    
    t.address=addr1;
    t.size=len;
    t.funcaddr=instr;
    
    table.push_back(t);
}
void markDataTainted(char *dest,char *src, char *srcend, int len, ADDRINT inst){
        int n =strlen(src);
        int count=0;
        int track=0;
    char instr[25];
    sprintf(instr,"0x%x",inst);
    
    //char *c=const_cast<char *>(addr1.c_str());
    
        for(int i=0;i<n;i++)

        {
                track=i;
                bool exist = checktable(src+i);
                if(exist){
                        count+=1;
                        if(count==len){
                                char addr[25];
                                sprintf(addr,"%p",dest);
                                t.address=addr;
                                t.size=count;
                            t.funcaddr=instr;
                           
                                table.push_back(t);
                        }

                }
                else{
                        int m=i-count-1;
                        char addr[25];
                        sprintf(addr,"%p",dest+m);
                        t.address=addr;
                        t.size=count;
                    t.funcaddr=instr;
                    
                        table.push_back(t);
                        count=0;
                }
        }
                if(count!=0 && count<track){
                int k=track-count;
                char addr[25];
                sprintf(addr,"%p",dest+k);
                t.address=addr;
                t.size=count;
                    t.funcaddr=instr;
                   
                table.push_back(t);

        }

}

int conversion(string hexVal) {
        hexVal.erase(0,2);
        unsigned int addr;
        stringstream s;
        s << std::hex << hexVal;
        s >> addr;
        return addr;
}
void clearTaintedData(char *startaddr,int len){
        char start[25];
        sprintf(start,"%p",startaddr);
        int count1=0;
        int reducedsize=0;
        int g=0;
        char finaladdr[25];
        sprintf(finaladdr,"%p",startaddr+len);
        for(size_t i = 0; i<table.size(); i++) {
                if(start == table[i].address ){
                        t.address=finaladdr;
                        t.size=table[i].size-len;
                        table.push_back(t);
                        table[i].address='0';
                        table[i].size=0;
                }
                else if(start >= table[i].address && start<=finaladdr)
                {
                        int n =table[i].size;
                        string str=table[i].address;
                        int hextoint=conversion(str);
                        int starttoint=conversion(start);
                        char start2hex[25];
                        sprintf(start2hex,"%X",starttoint);
                        for(int i=0;i<n;i++)
                        {
                                char signed2hex[25];
                                sprintf(signed2hex,"%X",hextoint+i);
                                if(strcmp(start2hex,signed2hex) == 0 )
                                {
                                        reducedsize=count1;
                                        g+=1;
                                        t.address=finaladdr;
                                        t.size=n-count1-len;
                                        table.push_back(t);

                                }
                                else{
                                        count1+=1;
                                }
                        }
                }
                if(g==1){

                        table[i].size=reducedsize;
                        g=0;
                }

        }
}
bool propagation(char *address)
{
        string str="0x";
        str.append(address);
        int returnaddr=conversion(str);
        char returnaddress[25];
        sprintf(returnaddress,"%x",returnaddr);
        for(size_t i=0;i<table.size();i++){
                string temp=table[i].address;
                int startaddr=conversion(temp);
                int n=table[i].size;
                for(int i=0;i<n;i++)
                {
                        char checkaddress[25];
                        sprintf(checkaddress,"%x",startaddr+i);
                        if(strcmp(returnaddress,checkaddress) == 0 )
                        {      // printTable();
                                        //cout<<"\n[TAINTBYTE]: "<<checkaddress<<"\n";
                                return true;

                        }
                }
        }
        return false;
}
void addstacktrace(string addr){
    //char instr[25];
    //sprintf(instr,"%p",addr);
    //string addres=instr;
    //cout<<"\naddr "<<addr;
   // int n=stackdata.size();
    for(size_t i=0;i<table.size();i++){
        if(table[i].address==addr){
            stringstream s;
            //vector<string>::iterator t;
            for(uint j=0;j<stackdata.size();j++){
                s<<" ";
                s<<stackdata[j];
                s<<" ";
            }
            string stacktrace=s.str();
            table[i].stacktrace=stacktrace;
           // printvector();
    }
}
}
void removeduplicate(){
    for (size_t lpo = 0; lpo < stackdata.size(); lpo++)
    {
        for (size_t lp = lpo + 1; lp < stackdata.size(); lp++)  //  lp needs to stay 1 ahead of lpo.
        {
            if (stackdata[lpo] == stackdata[lp])
            {
                stackdata.erase(stackdata.begin() + lp);  //  Also resizes the vector.
            }
        }
    }
    
}
string addsstacktrace(){
    //cout<<"\nffffff";
    string stacktrace;
    removeduplicate();
    //cout<<"\nTable sizeeee"<<table.size();
        //cout<<"\njjjjjj";
            stringstream s;
            //vector<string>::iterator t;
            for(uint j=0;j<stackdata.size();j++){
                s<<" ";
                s<<stackdata[j];
                s<<" ";
            }
             stacktrace=s.str();
            //table[i].stacktrace=stacktrace;
            // printvector();
            //return stacktrace;
    
    
    //cout<<"\nendddddd";
    return stacktrace;
}
int checkrange(string addr,string addr1,int n){
    char *c=const_cast<char *>(addr.c_str());
    char addres[25];
    sprintf(addres,"%s",c);
    int addr1toint=conversion(addr1);
    
    if(n==0){
            return 2;
        
    }
    else{
        for(int i=0;i<n;i++){
             char addr1tohex[25];
            sprintf(addr1tohex,"0x%x",addr1toint+i);
            if(strcmp(addr1tohex,addres) == 0){
                
                return 1;
        }
    }
    
}
    return 2;
}
void printStack(char* addr)
{
    //cout<<"\naddr"<<addr;
    int z=0;
    for(size_t i=0;i<table.size();i++){
        //string dummy=table[i].addr1;
        //if(!dummy.empty()){
        int check=checkrange(addr,table[i].address,table[i].size);
            if(check==2){
                cout<<"\nStack "<<z++<<": "<<"History of Mem("<<table[i].address<<"):"<<table[i].stacktrace ;
            }
            else if(check==1){
                cout<<"\nStack "<<z++<<": "<<"History of Mem("<<addr<<"): "<<table[i].stacktrace;
                cout<<"\n********************************************************************************************";
                printf("\n******Overflow detected*******");
                PIN_ExitProcess(1);
            }
        }
    }
/*void printStacks(char* addr)
{
    //cout<<"\naddr"<<addr;
    int z=0;
    for(size_t i=0;i<regis.size();i++){
        //string dummy=table[i].addr1;
        //if(!dummy.empty()){
        //int check=checkrange(addr,table[i].address,table[i].size);
        
            cout<<"\nStack "<<z++<<": "<<"History of Mem("<<regis[i].address<<"):"<<table[i].stacktrace ;
            //cout<<"\nStack "<<z++<<": "<<"History of Mem("<<addr<<"): "<<table[i].stacktrace;
            //cout<<"\n********************************************************************************************";
            //printf("\n******Overflow detected*******");
            //PIN_ExitProcess(1);
        }
    }

//}*/
INT32 Usage()
{
        return -1;
}
bool isStdin(FILE *fd)
{
        int ret = org_fileno(fd);
        if(ret == 0) return true;
        return false;
}
bool fgets_stdin = false;
VOID fgetsTail(char* ret, ADDRINT inst)
{
    char addr[25];
    sprintf(addr,"%p",ret);
        if(fgets_stdin) {
                markDataTainted(ret,strlen(ret),inst,addsstacktrace());
                printTaint(ret,strlen(ret));
            //addstacktrace(addr);
        }
        fgets_stdin = false;
}

VOID fgetsHead(char* dest, int size, FILE *stream)
{
        if(isStdin(stream)) {
                fgets_stdin = true;
        }
}
VOID getsTail(char* dest, ADDRINT inst)
{
    char addr[25];
    sprintf(addr,"%p",dest);
        markDataTainted(dest,strlen(dest),inst,addsstacktrace());
printTaint(dest,strlen(dest));
    //addstacktrace(addr);
}

VOID mainHead(int argc, char* argv[],ADDRINT inst)
{
    char instr[25];
    sprintf(instr,"0x%x",inst);
    stackdata.push_back(instr);
    mainaddress=instr;
        if(argc>1){
                int len=0;
                for(int i=1;i<argc;i++){
                    char addr[25];
                    sprintf(addr,"%p",argv[i]);
                        len=strlen(argv[i]);
                        markDataTainted(argv[i],len,inst,addsstacktrace());
                        printTaint(argv[i],len);
                    //cout<<"\nbefore push main";
                    //printvector();
                    
                    //cout<<"\nafter push main";
                    //printvector();
                    //addstacktrace(addr);
                     //printtable();
                }
        }
        else{
            stackdata.push_back(instr);
            //addstacktrace(inst);
        }
    //printtable();

}
VOID strcpyHead(char* dest, char* src,ADDRINT inst)
{
    char addr[25];
    sprintf(addr,"%p",dest);

        markDataTainted(dest,src,strlen(src),inst,addsstacktrace());
    
        char instr[25];
        sprintf(instr,"0x%x",inst);
    //cout<<"\nSTRCPY HEAD"<< instr;
    
         //printtable();

}
VOID bzeroHead(void* dest, int n)
{

        clearTaintedData((char*)dest,n);

}
VOID strncpyHead(char* dest, char* src, int count, ADDRINT inst)
{

        char srcend[25];
        sprintf(srcend,"%p",src+count);
        markDataTainted(dest,src,srcend,count,inst);
        char instr[25];
        sprintf(instr,"%x",inst);
       // dataStackTrace(src,dest,count,instr);

}
VOID strcatHead(char* dest, char* src, ADDRINT inst)
{
        catDataTainted(dest,strlen(src),inst);
    

}
VOID strncatHead(char* dest, char* src, int count, ADDRINT inst)
{

        catDataTainted(dest,count,inst);

}
VOID memcpyHead(char* dest, char* src, int count, ADDRINT inst )
{

        char srcend[25];
        sprintf(srcend,"%p",src+count);
        markDataTainted(dest,src,srcend,count,inst);


}
VOID memsetHead(void *dest,int ch,size_t n)
{
        clearTaintedData((char*)dest,static_cast<int>(n));

}
VOID retBefore(ADDRINT inst, ADDRINT addr, ADDRINT target)
{
    

        char addres[25];
        sprintf(addres,"%x",addr);
        string str="0x";
        str.append(addres);
        char *c=const_cast<char *>(str.c_str());
        char instr[25];
        sprintf(instr,"0x%x",inst);
        char targets[25];
        sprintf(targets,"%x",target);
    
        bool exist=propagation(addres);
        if(exist){
                 cout<<"\n***************************************overflow detected************************************";
                 cout<<"\nIndirectbranch("<<instr<<"):"<< "jump to "<<targets<<", stored in tainted byte("<<addres<<")";
                //printTable();
            //printvector();
                 printStack(c);
            
            
            
        }

}
int checkreg(UINT32 addr){
    char regis1[25];
    sprintf(regis1,"REG%u",addr);
    string str=regis1;
    //cout<<"\n"<<regis;
    for(size_t i=0;i<regis.size();i++){
        if(str==regis[i].address){
            return 1;
        }
    }
    
    return 0;
    
}
VOID branchreg(ADDRINT inst, ADDRINT target, UINT32 reg)
{
    
    
    char addres[25];
    sprintf(addres,"REG%u",reg);
    string str=addres;
    //str.append(addres);
    //char *c=const_cast<char *>(str.c_str());
    char instr[25];
    sprintf(instr,"0x%x",inst);
    char targets[25];
    sprintf(targets,"%x",target);
    
    int exist=checkreg(reg);
    if(exist==1){
        cout<<"\n***************************************overflow detected************************************";
        cout<<"\nIndirectbranch("<<instr<<"):"<< "jump to "<<targets<<", stored in tainted byte("<<addres<<")";
        //printTable();
        //printvector();
        //printStacks(c);
      cout<<"\n********************************************************************************************";
        printf("\n******Overflow detected*******");
        PIN_ExitProcess(1);
        }
    
}
/*string converttoString(char *instr,int size){
    string s="";
    for(int i=0;i<size;i++){
        s=s+instr[i];
    }
    return s;
}*/

/*void addstack(ADDRINT inst ){
    
    
    int status;
    char instr[25];
    sprintf(instr,"%x",inst);
    string addres=instr;
    string str="0x";
    str.append(addres);
    char *c=const_cast<char *>(str.c_str());
    status=check_stack(c);
    if(status==1){
        cout<<"\nstack push"<<str;
        stackdata.push_back(str);
        //printvector();
        addstacktrace();
        
    }
}*/
/*void addsstack(UINT32 inst ){
    
    
    //int status;
    char instr[25];
    sprintf(instr,"REG%u",inst);
    string str=instr;
    //char *c=const_cast<char *>(str.c_str());
    for(size_t i=0;i<table.size();i++){
        if(str==table[i].address){
        stackdata.push_back(str);
            //cout<<"\nyesssssss";
        //printvector();
        addstacktrace();
            printTable();
        }
    }
}*/
int checktaint(ADDRINT addr){
    char memop[25];
    sprintf(memop,"0x%x",addr);
    for(size_t i=0;i<table.size();i++){
        int hextoint=conversion(table[i].address);
        for(int j=0;j<table[i].size;j++){
            char hexval[25];
            sprintf(hexval,"0x%x",hextoint+j);
            //cout<<"\n"<<hexval;
            if(strcmp(memop,hexval) == 0){
                return 1;
            }
        }
    }
    return 0;
}
int checktaints(UINT32 addr){
    char regis1[25];
    sprintf(regis1,"REG%u",addr);
    string str=regis1;
    //cout<<"\n"<<regis;
    for(size_t i=0;i<regis.size();i++){
            if(str==regis[i].address){
                return 1;
            }
        }
    
    return 0;
    
}
void markregtainted(UINT32 reg,ADDRINT inst,string stack){
    char regis1[25];
    sprintf(regis1,"REG%u",reg);
    char memop[25];
    sprintf(memop,"0x%x",inst);
    r.address=regis1;
    r.size=0;
    r.funcaddr=memop;
    r.stacktrace=stack;
    regis.push_back(r);
    
    
}
void markmemtainted(ADDRINT addr,ADDRINT inst,string stack){
    char addres[25];
    sprintf(addres,"0x%x",addr);
    char instr[25];
    sprintf(instr,"0x%x",inst);
    t.address=addr;
    t.size=0;
    t.funcaddr=inst;
    t.stacktrace=stack;
    table.push_back(t);
    
}
void checkregtainted(UINT32 reg){
    char regis1[25];
    sprintf(regis1,"REG%u",reg);
   for(size_t i=0;i<regis.size();i++){
       if(regis1==regis[i].address){
           regis.erase(regis.begin()+i,regis.begin()+1+i);
           //stackdata.pop_back();
              }
    
}
}
void checkmemtainted(ADDRINT mem){
    char memop[25];
    sprintf(memop,"0x%x",mem);
    for(size_t i=0;i<table.size();i++){
        if(memop==table[i].address){
            table.erase(table.begin()+i,table.begin()+1+i);
            //stackdata.pop_back();
        }
        
    }
}
void memtoreg(ADDRINT inst, UINT32 count,UINT32 reg,ADDRINT addr,string ptr){
    int check=checktaint(addr);
    char instr[25];
    sprintf(instr,"0x%x",inst);
    //char addres[25];
    //sprintf(addres,"0x%x",);
    if(check==1){
         stackdata.push_back(instr);
        markregtainted(reg,inst,addsstacktrace());
       
        //char regis[25];
        //sprintf(regis,"REG%u",reg);
        //string str=regis;
        //addstacktrace(regis);
        //printTable();
    }
    else{
        checkregtainted(reg);
        //cout<<"\nREGISTER REMOVED TO TABLE";
        //printTable();
        //printTable();
    }
    
}
void regtomem(ADDRINT inst,UINT32 count,UINT32  reg,ADDRINT addr, string ptr){
    char instr[25];
    sprintf(instr,"0x%x",inst);
   int check=checktaints(reg);
    if(check==1)
    {
        stackdata.push_back(instr);
        markmemtainted(addr,inst,addsstacktrace());
        
    }
    else{
        checkmemtainted(addr);
    }
}
void regtoreg(ADDRINT inst,UINT32 count,UINT32 reg1,UINT32 reg2, string ptr){
    char instr[25];
    sprintf(instr,"0x%x",inst);
    int r1=checktaints(reg1);
    if(r1==1){
        stackdata.push_back(instr);
        markregtainted(reg2,inst,addsstacktrace());
    }
    else{
        checkregtainted(reg2);
    }
}
bool IsAddressInMainExecutable(ADDRINT inst)
{
    PIN_LockClient();
    RTN rtn = RTN_FindByAddress(inst);
    PIN_UnlockClient();
    if (rtn == RTN_Invalid())
        return false;
    
    SEC sec = RTN_Sec(rtn);
    if (sec == SEC_Invalid())
        return false;
    
    IMG img = SEC_Img(sec);
    if (img == IMG_Invalid())
        return false;
    if(IMG_IsMainExecutable(img)) return true;
    
    return false;
}

VOID isCall(ADDRINT inst)
{
    if(IsAddressInMainExecutable(inst))
    {
            char instr[25];
            sprintf(instr,"0x%x",inst);
        string str=instr;
        //cout<<"\nIScall"<<instr;
        if (stackdata.size() > 0 && stackdata[0] == mainaddress && stackdata[0]!=str){
            //cout<<"\nbefore push iscall"<<endl;
            //printvector();
            stackdata.push_back(instr);
            //cout<<"\nAfter push iscall"<<endl;
            //printvector();
            //addstacktrace(inst);
        
        }
    }
 //printvector();
}


VOID isRet(ADDRINT inst, ADDRINT target)
{
    //char instr[25];
    //sprintf(instr,"0x%x",target);
    //cout<<"\ntarget"<<target;
    if(IsAddressInMainExecutable(target))
    {
        if (stackdata.size() > 0 && stackdata[0] == mainaddress){
        stackdata.pop_back();
        }
    }
    //printvector();
    }


VOID Instruction(INS ins, VOID *v)
{
        if(INS_IsIndirectBranchOrCall(ins)){
                if(INS_IsMemoryRead(ins)) {
                        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) retBefore,
                                        IARG_INST_PTR,
                                        IARG_MEMORYREAD_EA,
                                        IARG_BRANCH_TARGET_ADDR,
                                        IARG_END);
                }
            if (INS_OperandRead(ins, 0) && INS_OperandIsReg(ins,0))
            {
                REG reg = INS_OperandReg(ins,0);
                INS_InsertCall(ins,IPOINT_BEFORE, (AFUNPTR)branchreg,
                               IARG_INST_PTR,
                               IARG_BRANCH_TARGET_ADDR,
                               IARG_UINT32, reg,
                               IARG_END);
            }
           
        }
    if(INS_IsCall(ins))
    {
        RTN rtn = RTN_FindByAddress(INS_Address(ins));
        
        if (RTN_Valid(rtn))
        {
            INS_InsertCall(ins,IPOINT_BEFORE, (AFUNPTR)isCall,
                           IARG_INST_PTR,
                           IARG_END);
        }
    }
    if(INS_IsRet(ins))
    {
       
        RTN rtn = RTN_FindByAddress(INS_Address(ins));
        
        if (RTN_Valid(rtn))
        {
            INS_InsertCall(ins,IPOINT_BEFORE, (AFUNPTR)isRet,
                           IARG_INST_PTR,
                           IARG_BRANCH_TARGET_ADDR,
                           IARG_END);
        }
        
    }
    
    

    if(INS_OperandCount(ins) > 1 && INS_OperandRead(ins, 1) && INS_OperandWritten(ins,0)){
        if(INS_MemoryOperandIsRead(ins, 0) && INS_OperandIsReg(ins, 0)){
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) memtoreg,
                           IARG_INST_PTR,
                           IARG_UINT32, INS_OperandCount(ins),
                           IARG_UINT32, INS_OperandReg(ins,0),
                           IARG_MEMORYOP_EA,0,
                           IARG_PTR,new string(INS_Disassemble(ins)),
                           IARG_END);
        }
        else if(INS_MemoryOperandIsWritten(ins, 0) && INS_OperandIsReg(ins, 1)){
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) regtomem,
                           IARG_INST_PTR,
                           IARG_UINT32,INS_OperandCount(ins),
                           IARG_UINT32, INS_OperandReg(ins,1),
                           IARG_MEMORYOP_EA,0,
                           IARG_PTR,new string(INS_Disassemble(ins)),
                           IARG_END);
        }
        else if(INS_OperandIsReg(ins, 0) && INS_OperandIsReg(ins, 1)){
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) regtoreg,
                           IARG_INST_PTR,
                           IARG_UINT32, INS_OperandCount(ins),
                           IARG_UINT32, REG(INS_OperandReg(ins,0)),
                           IARG_UINT32, REG(INS_OperandReg(ins,1)),
                           IARG_PTR,new string(INS_Disassemble(ins)),
                           IARG_END);
        }
        
        
    }

}

VOID Image(IMG img, VOID *v) {
        RTN rtn;

        rtn = RTN_FindByName(img, FGETS);
        if(RTN_Valid(rtn)) {
                RTN_Open(rtn);
                RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)fgetsHead,
                                IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                                IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                                IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
                               IARG_INST_PTR,
                                IARG_END);

                RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)fgetsTail,
                                IARG_FUNCRET_EXITPOINT_VALUE,
                                IARG_END);
                RTN_Close(rtn);
        }

        rtn = RTN_FindByName(img, GETS);
        if(RTN_Valid(rtn)) {
                RTN_Open(rtn);
                RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)getsTail,
                                IARG_FUNCRET_EXITPOINT_VALUE,
                               IARG_INST_PTR,
                                IARG_END);
                RTN_Close(rtn);
        }
        rtn = RTN_FindByName(img, STRCPY);
        if(RTN_Valid(rtn)) {
                RTN_Open(rtn);
                RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)strcpyHead,
                                IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                                IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                                IARG_INST_PTR,
                                IARG_END);
                RTN_Close(rtn);
        }

        rtn = RTN_FindByName(img, BZERO);
        if(RTN_Valid(rtn)) {
                RTN_Open(rtn);
                RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)bzeroHead,
                                IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                                IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                                IARG_END);
                RTN_Close(rtn);
        }
        rtn = RTN_FindByName(img, MEMSET);
        if(RTN_Valid(rtn)) {
                RTN_Open(rtn);
                RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)memsetHead,
                                IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                                IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                                IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
                                IARG_END);
                RTN_Close(rtn);
        }
        rtn = RTN_FindByName(img, STRNCPY);
        if(RTN_Valid(rtn)) {
                RTN_Open(rtn);
                RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)strncpyHead,
                                IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                                IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                                IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
                                IARG_INST_PTR,
                                IARG_END);
                RTN_Close(rtn);
        }
        rtn = RTN_FindByName(img, STRCAT);
        if(RTN_Valid(rtn)) {
                RTN_Open(rtn);
                RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)strcatHead,
                                IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                                IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                                IARG_INST_PTR,
                                IARG_END);
                RTN_Close(rtn);
        }
        rtn = RTN_FindByName(img, STRNCAT);
        if(RTN_Valid(rtn)) {
                RTN_Open(rtn);
                RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)strncatHead,
                                IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                                IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                                IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
                                IARG_INST_PTR,
                                IARG_END);
                RTN_Close(rtn);
         }
        rtn = RTN_FindByName(img, MEMCPY);
        if(RTN_Valid(rtn)) {
                RTN_Open(rtn);
                RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)memcpyHead,
                                IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                                IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                                IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
                                IARG_INST_PTR,
                                IARG_END);
                RTN_Close(rtn);
        }


        rtn = RTN_FindByName(img, MAIN);
        if(RTN_Valid(rtn)) {
                RTN_Open(rtn);
                RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)mainHead,
                                IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                                IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                                IARG_INST_PTR,
                                IARG_END);
                RTN_Close(rtn);
        }
                rtn = RTN_FindByName(img, FILENO);
        if(RTN_Valid(rtn)) {
                RTN_Open(rtn);
                AFUNPTR fptr = RTN_Funptr(rtn);
                org_fileno = (FP_FILENO)(fptr);
                RTN_Close(rtn);
        }
    
    
    
    
}



int main(int argc, char *argv[])
{
    
        PIN_InitSymbols();
    
        if(PIN_Init(argc, argv)){
                return Usage();
        }
    
    
        IMG_AddInstrumentFunction(Image, 0);
        INS_AddInstrumentFunction(Instruction, 0);
    
    
        PIN_StartProgram();
        return 0;
}
        

