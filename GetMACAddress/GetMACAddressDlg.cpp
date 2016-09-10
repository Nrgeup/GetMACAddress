
// GetMACAddressDlg.cpp : 实现文件
//

#include "stdafx.h"
#include "GetMACAddress.h"
#include "GetMACAddressDlg.h"
#include "afxdialogex.h"
#include "pcap.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// 用于应用程序“关于”菜单项的 CAboutDlg 对话框
//全局变量
pcap_t* afx_adhandle;         //当前打开的网络接口
struct pcap_pkthdr *afx_header;		//捕获数据报的头部
const u_char *afx_pkt_data;			//捕获数据报数据
//ARPFrame_t afx_ARPFrame;


class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// 对话框数据
	enum { IDD = IDD_ABOUTBOX };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

// 实现
protected:
	DECLARE_MESSAGE_MAP()
public:
//	afx_msg void OnReturn();
//	afx_msg void OnClose();
};

CAboutDlg::CAboutDlg() : CDialogEx(CAboutDlg::IDD)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
//	ON_COMMAND(IDC_RETURN, &CAboutDlg::OnReturn)
//	ON_WM_CLOSE()
END_MESSAGE_MAP()


// CGetMACAddressDlg 对话框



CGetMACAddressDlg::CGetMACAddressDlg(CWnd* pParent /*=NULL*/)
	: CDialogEx(CGetMACAddressDlg::IDD, pParent)
	, m_IP(0)
	, m_alldevs(NULL)
	, m_this_broad(0)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
	m_if_get_this_mac=false;
	
	//获得本机的设备列表
	char  errbuf[PCAP_ERRBUF_SIZE];	//错误信息缓冲区
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, 	//获取本机的接口设备
			NULL,			       //无需认证
			&m_alldevs, 		       //指向设备列表首部
			errbuf			      //出错信息保存缓存区
			) == -1){
		/*错误处理,结果为-1代表出现获取适配器列表失败*/
		MessageBox(L"获取本机设备列表失败："+CString(errbuf),MB_OK);}

	//if(m_this_ip==0)
		//m_alldevs=m_alldevs->next;
	
	m_selectdevs=m_alldevs;

}

void CGetMACAddressDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_LIST1, mc_Message);
	DDX_Control(pDX, IDC_LIST2, m_list);
	DDX_IPAddress(pDX, IDC_IPADDRESS1, m_IP);
	DDX_Control(pDX, IDC_GET, mc_get);
	DDX_Control(pDX, IDC_RETURN, mc_return);
}

BEGIN_MESSAGE_MAP(CGetMACAddressDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_WM_CLOSE()
	ON_NOTIFY(IPN_FIELDCHANGED, IDC_IPADDRESS1, &CGetMACAddressDlg::OnIpnFieldchangedIpaddress1)
	ON_BN_CLICKED(IDOK, &CGetMACAddressDlg::OnBnClickedOk)
	ON_BN_CLICKED(IDC_GET, &CGetMACAddressDlg::OnBnClickedGet)
	ON_BN_CLICKED(IDC_RETURN, &CGetMACAddressDlg::OnClickedReturn)
END_MESSAGE_MAP()


// CGetMACAddressDlg 消息处理程序

BOOL CGetMACAddressDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// 将“关于...”菜单项添加到系统菜单中。

	// IDM_ABOUTBOX 必须在系统命令范围内。
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != NULL)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// 设置此对话框的图标。当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	// TODO: 在此添加额外的初始化代码

	mc_Message.ResetContent();//清除原有框的内容
	mc_Message.AddString(CString(m_selectdevs->name));			//显示该网络接口设备的名字
	mc_Message.AddString(CString(m_selectdevs->description));	//显示该网络接口设备的描述信息

	pcap_addr_t	*a;
	CString output1,output2,output3,output4;
	bool ok=0;
	while(1){	
		for(a=m_selectdevs->addresses; a!=NULL; a=a->next){
			if(a->addr->sa_family==AF_INET){  //判断该地址是否IP地址
			
				m_this_ip=ntohl(((struct sockaddr_in *)a->addr)->sin_addr.s_addr);  //显示IP地址
				
				output2=L"IP地址： "+long2ip(m_this_ip);

				m_this_netmask=ntohl(((struct sockaddr_in *)a->netmask)->sin_addr.s_addr);  //显示地址掩码
				if(m_this_netmask!=((((255*256)+255)*256+255)*256+0))	//获取地址掩码为255.255.255.0的网络
				//if(m_this_netmask!=((((255*256)+252)*256+0)*256+0))
					break;
				ok=1;
				output3=L"地址掩码: "+long2ip(m_this_netmask);

				m_this_broad=ntohl(((struct sockaddr_in *)a->broadaddr)->sin_addr.s_addr);  //显示广播地址
				output4=L"广播地址: "+long2ip(m_this_broad);
			}
		}
		if(ok)
			break;
		m_selectdevs=m_selectdevs->next;
	}

	//获得本机MAC地址
	GetSelfMac();
	
	if(!m_if_get_this_mac){
		AfxMessageBox(L"获取本机MAC地址失败!",MB_OK|MB_ICONERROR);
		mc_get.EnableWindow(false);
	}
	else{
		for(int i=0;i<6;i++)
			m_this_mac[i]=m_MAC[i];
	}

	output1.Format(L"MAC地址： "+char2mac(m_this_mac));

	mc_Message.AddString(output1);
	mc_Message.AddString(output2);
	mc_Message.AddString(output3);
	mc_Message.AddString(output4);
	
	m_IP=m_this_ip;
	//m_IP=ntohl(inet_addr("192.168.191.2"));
	UpdateData(FALSE);

	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

void CGetMACAddressDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void CGetMACAddressDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作区矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

//当用户拖动最小化窗口时系统调用此函数取得光标
//显示。
HCURSOR CGetMACAddressDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}



void CGetMACAddressDlg::OnClose()
{
	// TODO: 在此添加消息处理程序代码和/或调用默认值
	pcap_freealldevs(m_alldevs); //释放设备列表
	CDialogEx::OnClose();
}

//数据包捕获工作者线程
UINT Capturer(LPVOID pParm)
{
	CGetMACAddressDlg* dlg = (CGetMACAddressDlg*)theApp.m_pMainWnd; //获取对话框句柄

	char errbuff[1000];
	memset(errbuff,0,sizeof(errbuff));

	if ((afx_adhandle= pcap_open(dlg->m_selectdevs->name,	// 设备名称
	  65536,	 // WinPcap获取网络数据包的最大长度
	  PCAP_OPENFLAG_PROMISCUOUS,	// 混杂模式
	  1000,	 // 读超时为1秒
	  NULL,
	  errbuff	// error buffer
	  ) ) == NULL)
	{
		AfxMessageBox(L"打开该设备网卡接口失败!",MB_OK|MB_ICONERROR);
		return -1;
	}

	//利用pcap_next_ex函数捕获数据包
	/* 此处循环调用 pcap_next_ex来接受数据报*/ 
	int res;
	while(res = pcap_next_ex(afx_adhandle,&afx_header,&afx_pkt_data)>=0){
		if(res==0)  //超时情况
			continue;

		ARPFrame_t* arp=(ARPFrame_t*) afx_pkt_data;
		if(!dlg->m_if_get_this_mac&&(ntohs(arp->FrameHeader.FrameType)==0x0806)&&((arp->Operation)==htons(0x0002))&&(arp->RecvIP==htonl(dlg->m_IP)))	/*0x0002:ARP应答*/
		{
			dlg->m_get_state=true;
			for(int i=0;i<6;i++)
				dlg->m_MAC[i]=arp->SendHa[i];
			//AfxMessageBox(L"获得本机MAC地址成功!",MB_OK);
		}
		if(dlg->m_if_get_this_mac&&(ntohs(arp->FrameHeader.FrameType)==0x0806)&&((arp->Operation)==htons(0x0002))&&(arp->SendIP==htonl(dlg->m_IP)))
		{
			dlg->m_get_state=true;
			for(int i=0;i<6;i++)
				dlg->m_MAC[i]=arp->SendHa[i];
			//AfxMessageBox(L"获得目的主机MAC地址成功!",MB_OK);
		}

	}
	if(res==-1)  //获取数据包错误
	{
		AfxMessageBox(L"获取数据包错误!",MB_OK|MB_ICONERROR);
	}

	return 0;
}


int CGetMACAddressDlg::SendARP(BYTE* SrcMAC,BYTE* SendHa,DWORD SendIp,DWORD RecvIp)
{
	
	CGetMACAddressDlg* dlg = (CGetMACAddressDlg*)theApp.m_pMainWnd; //获取对话框句柄
	char errbuff[1000];
	memset(errbuff,0,sizeof(errbuff));
	if ((afx_adhandle= pcap_open(dlg->m_selectdevs->name,	// 设备名称
	  65536,	 // WinPcap获取网络数据包的最大长度
	  PCAP_OPENFLAG_PROMISCUOUS,	// 混杂模式
	  1000,	 // 读超时为1秒
	  NULL,
	  errbuff	// error buffer
	  )) == NULL)
	{
		AfxMessageBox(L"打开该设备网卡接口失败!",MB_OK|MB_ICONERROR);
		return -1;
	}
	
	ARPFrame_t  ARPFrame;		
	ARPFrame.FrameHeader.FrameType=htons(0x0806);	//帧类型为ARP
	ARPFrame.HardwareType=htons(0x0001);			//硬件类型为以太网
	ARPFrame.ProtocolType=htons(0x0800);			//协议类型为IP
	ARPFrame.HLen=6;								//硬件地址长度为6
	ARPFrame.PLen=4;								//协议地址长度为4
	ARPFrame.Operation =htons(0x0001);				//操作为ARP请求
	ARPFrame.SendIP=SendIp;//将ARPFrame.SendIP设置为本机网卡上绑定的IP地址。	
	ARPFrame.RecvIP=RecvIp;		//将ARPFrame.RecvIP设置为请求的IP地址;


	for(int i=0;i<6;i++)
	{
		ARPFrame.FrameHeader.DesMAC[i]=0xff;	//将ARPFrame.FrameHeader.DesMAC设置为广播地址。
		ARPFrame.FrameHeader.SrcMAC[i]=SrcMAC[i];		
		ARPFrame.SendHa[i]=SendHa[i];	//将ARPFrame.SendHa设置为本机网卡的MAC地址。
		ARPFrame.RecvHa[i]=0x00;		//将ARPFrame.RecvHa设置为0。
	}

	if (pcap_sendpacket(afx_adhandle, (u_char *) &ARPFrame,
		sizeof(ARPFrame_t))!= 0)
	{
		//发送错误处理
		m_list.AddString(L"获取IP地址： "+long2ip(RecvIp) + L" 的MAC地址失败！");
	}
	return 0;
}

/* 将数字类型的IP地址转换成字符串类型的 */
CString CGetMACAddressDlg::long2ip(DWORD in)
{
	DWORD mask[] ={0xFF000000,0x00FF0000,0x0000FF00,0x000000FF};
	DWORD num[4];

	num[0]=in&mask[0];
	num[0]=num[0]>>24;

	num[1]=in&mask[1];
	num[1]=num[1]>>16;

	num[2]=in&mask[2];
	num[2]=num[2]>>8;

	num[3]=in&mask[3];

	CString ans;
	ans.Format(L"%03d.%03d.%03d.%03d",num[0],num[1],num[2],num[3]);
	return ans;
}

/* 将字符串类型的IP地址转换成数字类型的 */
DWORD CGetMACAddressDlg::ip2long (CString in)
{
    DWORD ans=0,temp;
	int size=in.GetLength();

	for(int i=0;i<size;i++)
	{
		if(in[i]=='.'){
			ans=ans*256+temp;
			temp=0;
			continue;
		}
		temp=temp*10+in[i]-'0';
	}
	ans=ans*256+temp;
	return ans;
}

/* 将char*类型的MAC地址转换成字符串类型的 */
CString CGetMACAddressDlg::char2mac(BYTE* MAC)
{
	CString ans;
	ans.Format(L"%02X-%02X-%02X-%02X-%02X-%02X",int(MAC[0]),int(MAC[1]),int(MAC[2]),int(MAC[3]),int(MAC[4]),int(MAC[5]));
	return ans;
}

//获取自己主机的MAC地址
int CGetMACAddressDlg::GetSelfMac(void)
{
	/*************************************************************
	 *本地主机模拟一个远端主机，发送一个ARP请求报文，
	 *该请求报文请求本机网络接口上绑定的IP地址与MAC地址的对应关系
	*************************************************************/

	//创建工作者线程
	m_Capturer=AfxBeginThread((AFX_THREADPROC)Capturer,NULL,THREAD_PRIORITY_NORMAL);  
	if(m_Capturer ==NULL ){
		AfxMessageBox(L"启动捕获数据包线程失败!",MB_OK|MB_ICONERROR);
		return FALSE;
	}
	

	//随机设置源MAC地址
	BYTE SrcMAC[6],SendHa[6];
	for(int i=0;i<6;i++){
		SrcMAC[i]=0x66;
		SendHa[i]=0x66;
	}

	DWORD SendIp,RecvIp;
	
	SendIp=inet_addr("112.112.112.112"); //随便设的请求方ip
	RecvIp=htonl(m_this_ip);		//将接受方IP设置成本机IP
	m_IP=SendIp;
	::Sleep(40);
	m_get_state=false;
	SendARP(SrcMAC,SendHa,SendIp,RecvIp);	//发送ARP请求报
	::Sleep(5000);//等待获取成功
	if(m_get_state)
		m_if_get_this_mac=true;

	return 0;
}


void CGetMACAddressDlg::OnIpnFieldchangedIpaddress1(NMHDR *pNMHDR, LRESULT *pResult)
{
	LPNMIPADDRESS pIPAddr = reinterpret_cast<LPNMIPADDRESS>(pNMHDR);
	// TODO: 在此添加控件通知处理程序代码
	UpdateData(true);
	*pResult = 0;
}


void CGetMACAddressDlg::OnBnClickedOk()
{
	// TODO: 在此添加控件通知处理程序代码
	CDialogEx::OnOK();
}


void CGetMACAddressDlg::OnBnClickedGet()
{
	// TODO: 在此添加控件通知处理程序代码
	UpdateData(true);
	
	if(m_IP==m_this_ip){
		m_list.AddString(long2ip(m_IP)+L" --> "+char2mac(m_this_mac));
		m_list.SetCurSel(m_list.GetCount()-1);
		return;
	}
	
	BYTE SrcMAC[6], SendHa[6];
	DWORD SendIp, RecvIp;

	//将SendHa,SrcMAC设置为本机网卡的MAC地址
	for(int i=0;i<6;i++){
		SrcMAC[i]=m_this_mac[i];
		SendHa[i]=m_this_mac[i];
	}

	//将RecvIP设置为请求的IP地址;
	RecvIp=htonl(m_IP);

	//将SendIP设置为本机网卡上绑定的IP地址
	SendIp=htonl(m_this_ip);

	m_get_state=false;
	SendARP(SrcMAC,SendHa,SendIp,RecvIp);	//发送ARP请求报
	::Sleep(2000);//等待获取成功
	if(m_get_state){
		//获取成功
		m_list.AddString(long2ip(m_IP)+L" --> "+char2mac(m_MAC));
	}
	else{
		m_list.AddString(L"连接到 "+long2ip(m_IP)+ L" 超时！");
	}
	//将光标设定在最后一行
	m_list.SetCurSel(m_list.GetCount()-1);
}



void CGetMACAddressDlg::OnClickedReturn()
{
	// TODO: 在此添加控件通知处理程序代码
	m_list.ResetContent();//清除原有框的内容
}
