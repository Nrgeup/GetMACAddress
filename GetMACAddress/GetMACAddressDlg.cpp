
// GetMACAddressDlg.cpp : ʵ���ļ�
//

#include "stdafx.h"
#include "GetMACAddress.h"
#include "GetMACAddressDlg.h"
#include "afxdialogex.h"
#include "pcap.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// ����Ӧ�ó��򡰹��ڡ��˵���� CAboutDlg �Ի���
//ȫ�ֱ���
pcap_t* afx_adhandle;         //��ǰ�򿪵�����ӿ�
struct pcap_pkthdr *afx_header;		//�������ݱ���ͷ��
const u_char *afx_pkt_data;			//�������ݱ�����
//ARPFrame_t afx_ARPFrame;


class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// �Ի�������
	enum { IDD = IDD_ABOUTBOX };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV ֧��

// ʵ��
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


// CGetMACAddressDlg �Ի���



CGetMACAddressDlg::CGetMACAddressDlg(CWnd* pParent /*=NULL*/)
	: CDialogEx(CGetMACAddressDlg::IDD, pParent)
	, m_IP(0)
	, m_alldevs(NULL)
	, m_this_broad(0)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
	m_if_get_this_mac=false;
	
	//��ñ������豸�б�
	char  errbuf[PCAP_ERRBUF_SIZE];	//������Ϣ������
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, 	//��ȡ�����Ľӿ��豸
			NULL,			       //������֤
			&m_alldevs, 		       //ָ���豸�б��ײ�
			errbuf			      //������Ϣ���滺����
			) == -1){
		/*������,���Ϊ-1������ֻ�ȡ�������б�ʧ��*/
		MessageBox(L"��ȡ�����豸�б�ʧ�ܣ�"+CString(errbuf),MB_OK);}

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


// CGetMACAddressDlg ��Ϣ�������

BOOL CGetMACAddressDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// ��������...���˵�����ӵ�ϵͳ�˵��С�

	// IDM_ABOUTBOX ������ϵͳ���Χ�ڡ�
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

	// ���ô˶Ի����ͼ�ꡣ��Ӧ�ó��������ڲ��ǶԻ���ʱ����ܽ��Զ�
	//  ִ�д˲���
	SetIcon(m_hIcon, TRUE);			// ���ô�ͼ��
	SetIcon(m_hIcon, FALSE);		// ����Сͼ��

	// TODO: �ڴ���Ӷ���ĳ�ʼ������

	mc_Message.ResetContent();//���ԭ�п������
	mc_Message.AddString(CString(m_selectdevs->name));			//��ʾ������ӿ��豸������
	mc_Message.AddString(CString(m_selectdevs->description));	//��ʾ������ӿ��豸��������Ϣ

	pcap_addr_t	*a;
	CString output1,output2,output3,output4;
	bool ok=0;
	while(1){	
		for(a=m_selectdevs->addresses; a!=NULL; a=a->next){
			if(a->addr->sa_family==AF_INET){  //�жϸõ�ַ�Ƿ�IP��ַ
			
				m_this_ip=ntohl(((struct sockaddr_in *)a->addr)->sin_addr.s_addr);  //��ʾIP��ַ
				
				output2=L"IP��ַ�� "+long2ip(m_this_ip);

				m_this_netmask=ntohl(((struct sockaddr_in *)a->netmask)->sin_addr.s_addr);  //��ʾ��ַ����
				if(m_this_netmask!=((((255*256)+255)*256+255)*256+0))	//��ȡ��ַ����Ϊ255.255.255.0������
				//if(m_this_netmask!=((((255*256)+252)*256+0)*256+0))
					break;
				ok=1;
				output3=L"��ַ����: "+long2ip(m_this_netmask);

				m_this_broad=ntohl(((struct sockaddr_in *)a->broadaddr)->sin_addr.s_addr);  //��ʾ�㲥��ַ
				output4=L"�㲥��ַ: "+long2ip(m_this_broad);
			}
		}
		if(ok)
			break;
		m_selectdevs=m_selectdevs->next;
	}

	//��ñ���MAC��ַ
	GetSelfMac();
	
	if(!m_if_get_this_mac){
		AfxMessageBox(L"��ȡ����MAC��ַʧ��!",MB_OK|MB_ICONERROR);
		mc_get.EnableWindow(false);
	}
	else{
		for(int i=0;i<6;i++)
			m_this_mac[i]=m_MAC[i];
	}

	output1.Format(L"MAC��ַ�� "+char2mac(m_this_mac));

	mc_Message.AddString(output1);
	mc_Message.AddString(output2);
	mc_Message.AddString(output3);
	mc_Message.AddString(output4);
	
	m_IP=m_this_ip;
	//m_IP=ntohl(inet_addr("192.168.191.2"));
	UpdateData(FALSE);

	return TRUE;  // ���ǽ��������õ��ؼ������򷵻� TRUE
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

// �����Ի��������С����ť������Ҫ����Ĵ���
//  �����Ƹ�ͼ�ꡣ����ʹ���ĵ�/��ͼģ�͵� MFC Ӧ�ó���
//  �⽫�ɿ���Զ���ɡ�

void CGetMACAddressDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // ���ڻ��Ƶ��豸������

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// ʹͼ���ڹ����������о���
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// ����ͼ��
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

//���û��϶���С������ʱϵͳ���ô˺���ȡ�ù��
//��ʾ��
HCURSOR CGetMACAddressDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}



void CGetMACAddressDlg::OnClose()
{
	// TODO: �ڴ������Ϣ�����������/�����Ĭ��ֵ
	pcap_freealldevs(m_alldevs); //�ͷ��豸�б�
	CDialogEx::OnClose();
}

//���ݰ����������߳�
UINT Capturer(LPVOID pParm)
{
	CGetMACAddressDlg* dlg = (CGetMACAddressDlg*)theApp.m_pMainWnd; //��ȡ�Ի�����

	char errbuff[1000];
	memset(errbuff,0,sizeof(errbuff));

	if ((afx_adhandle= pcap_open(dlg->m_selectdevs->name,	// �豸����
	  65536,	 // WinPcap��ȡ�������ݰ�����󳤶�
	  PCAP_OPENFLAG_PROMISCUOUS,	// ����ģʽ
	  1000,	 // ����ʱΪ1��
	  NULL,
	  errbuff	// error buffer
	  ) ) == NULL)
	{
		AfxMessageBox(L"�򿪸��豸�����ӿ�ʧ��!",MB_OK|MB_ICONERROR);
		return -1;
	}

	//����pcap_next_ex�����������ݰ�
	/* �˴�ѭ������ pcap_next_ex���������ݱ�*/ 
	int res;
	while(res = pcap_next_ex(afx_adhandle,&afx_header,&afx_pkt_data)>=0){
		if(res==0)  //��ʱ���
			continue;

		ARPFrame_t* arp=(ARPFrame_t*) afx_pkt_data;
		if(!dlg->m_if_get_this_mac&&(ntohs(arp->FrameHeader.FrameType)==0x0806)&&((arp->Operation)==htons(0x0002))&&(arp->RecvIP==htonl(dlg->m_IP)))	/*0x0002:ARPӦ��*/
		{
			dlg->m_get_state=true;
			for(int i=0;i<6;i++)
				dlg->m_MAC[i]=arp->SendHa[i];
			//AfxMessageBox(L"��ñ���MAC��ַ�ɹ�!",MB_OK);
		}
		if(dlg->m_if_get_this_mac&&(ntohs(arp->FrameHeader.FrameType)==0x0806)&&((arp->Operation)==htons(0x0002))&&(arp->SendIP==htonl(dlg->m_IP)))
		{
			dlg->m_get_state=true;
			for(int i=0;i<6;i++)
				dlg->m_MAC[i]=arp->SendHa[i];
			//AfxMessageBox(L"���Ŀ������MAC��ַ�ɹ�!",MB_OK);
		}

	}
	if(res==-1)  //��ȡ���ݰ�����
	{
		AfxMessageBox(L"��ȡ���ݰ�����!",MB_OK|MB_ICONERROR);
	}

	return 0;
}


int CGetMACAddressDlg::SendARP(BYTE* SrcMAC,BYTE* SendHa,DWORD SendIp,DWORD RecvIp)
{
	
	CGetMACAddressDlg* dlg = (CGetMACAddressDlg*)theApp.m_pMainWnd; //��ȡ�Ի�����
	char errbuff[1000];
	memset(errbuff,0,sizeof(errbuff));
	if ((afx_adhandle= pcap_open(dlg->m_selectdevs->name,	// �豸����
	  65536,	 // WinPcap��ȡ�������ݰ�����󳤶�
	  PCAP_OPENFLAG_PROMISCUOUS,	// ����ģʽ
	  1000,	 // ����ʱΪ1��
	  NULL,
	  errbuff	// error buffer
	  )) == NULL)
	{
		AfxMessageBox(L"�򿪸��豸�����ӿ�ʧ��!",MB_OK|MB_ICONERROR);
		return -1;
	}
	
	ARPFrame_t  ARPFrame;		
	ARPFrame.FrameHeader.FrameType=htons(0x0806);	//֡����ΪARP
	ARPFrame.HardwareType=htons(0x0001);			//Ӳ������Ϊ��̫��
	ARPFrame.ProtocolType=htons(0x0800);			//Э������ΪIP
	ARPFrame.HLen=6;								//Ӳ����ַ����Ϊ6
	ARPFrame.PLen=4;								//Э���ַ����Ϊ4
	ARPFrame.Operation =htons(0x0001);				//����ΪARP����
	ARPFrame.SendIP=SendIp;//��ARPFrame.SendIP����Ϊ���������ϰ󶨵�IP��ַ��	
	ARPFrame.RecvIP=RecvIp;		//��ARPFrame.RecvIP����Ϊ�����IP��ַ;


	for(int i=0;i<6;i++)
	{
		ARPFrame.FrameHeader.DesMAC[i]=0xff;	//��ARPFrame.FrameHeader.DesMAC����Ϊ�㲥��ַ��
		ARPFrame.FrameHeader.SrcMAC[i]=SrcMAC[i];		
		ARPFrame.SendHa[i]=SendHa[i];	//��ARPFrame.SendHa����Ϊ����������MAC��ַ��
		ARPFrame.RecvHa[i]=0x00;		//��ARPFrame.RecvHa����Ϊ0��
	}

	if (pcap_sendpacket(afx_adhandle, (u_char *) &ARPFrame,
		sizeof(ARPFrame_t))!= 0)
	{
		//���ʹ�����
		m_list.AddString(L"��ȡIP��ַ�� "+long2ip(RecvIp) + L" ��MAC��ַʧ�ܣ�");
	}
	return 0;
}

/* ���������͵�IP��ַת�����ַ������͵� */
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

/* ���ַ������͵�IP��ַת�����������͵� */
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

/* ��char*���͵�MAC��ַת�����ַ������͵� */
CString CGetMACAddressDlg::char2mac(BYTE* MAC)
{
	CString ans;
	ans.Format(L"%02X-%02X-%02X-%02X-%02X-%02X",int(MAC[0]),int(MAC[1]),int(MAC[2]),int(MAC[3]),int(MAC[4]),int(MAC[5]));
	return ans;
}

//��ȡ�Լ�������MAC��ַ
int CGetMACAddressDlg::GetSelfMac(void)
{
	/*************************************************************
	 *��������ģ��һ��Զ������������һ��ARP�����ģ�
	 *�����������󱾻�����ӿ��ϰ󶨵�IP��ַ��MAC��ַ�Ķ�Ӧ��ϵ
	*************************************************************/

	//�����������߳�
	m_Capturer=AfxBeginThread((AFX_THREADPROC)Capturer,NULL,THREAD_PRIORITY_NORMAL);  
	if(m_Capturer ==NULL ){
		AfxMessageBox(L"�����������ݰ��߳�ʧ��!",MB_OK|MB_ICONERROR);
		return FALSE;
	}
	

	//�������ԴMAC��ַ
	BYTE SrcMAC[6],SendHa[6];
	for(int i=0;i<6;i++){
		SrcMAC[i]=0x66;
		SendHa[i]=0x66;
	}

	DWORD SendIp,RecvIp;
	
	SendIp=inet_addr("112.112.112.112"); //����������ip
	RecvIp=htonl(m_this_ip);		//�����ܷ�IP���óɱ���IP
	m_IP=SendIp;
	::Sleep(40);
	m_get_state=false;
	SendARP(SrcMAC,SendHa,SendIp,RecvIp);	//����ARP����
	::Sleep(5000);//�ȴ���ȡ�ɹ�
	if(m_get_state)
		m_if_get_this_mac=true;

	return 0;
}


void CGetMACAddressDlg::OnIpnFieldchangedIpaddress1(NMHDR *pNMHDR, LRESULT *pResult)
{
	LPNMIPADDRESS pIPAddr = reinterpret_cast<LPNMIPADDRESS>(pNMHDR);
	// TODO: �ڴ���ӿؼ�֪ͨ����������
	UpdateData(true);
	*pResult = 0;
}


void CGetMACAddressDlg::OnBnClickedOk()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������
	CDialogEx::OnOK();
}


void CGetMACAddressDlg::OnBnClickedGet()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������
	UpdateData(true);
	
	if(m_IP==m_this_ip){
		m_list.AddString(long2ip(m_IP)+L" --> "+char2mac(m_this_mac));
		m_list.SetCurSel(m_list.GetCount()-1);
		return;
	}
	
	BYTE SrcMAC[6], SendHa[6];
	DWORD SendIp, RecvIp;

	//��SendHa,SrcMAC����Ϊ����������MAC��ַ
	for(int i=0;i<6;i++){
		SrcMAC[i]=m_this_mac[i];
		SendHa[i]=m_this_mac[i];
	}

	//��RecvIP����Ϊ�����IP��ַ;
	RecvIp=htonl(m_IP);

	//��SendIP����Ϊ���������ϰ󶨵�IP��ַ
	SendIp=htonl(m_this_ip);

	m_get_state=false;
	SendARP(SrcMAC,SendHa,SendIp,RecvIp);	//����ARP����
	::Sleep(2000);//�ȴ���ȡ�ɹ�
	if(m_get_state){
		//��ȡ�ɹ�
		m_list.AddString(long2ip(m_IP)+L" --> "+char2mac(m_MAC));
	}
	else{
		m_list.AddString(L"���ӵ� "+long2ip(m_IP)+ L" ��ʱ��");
	}
	//������趨�����һ��
	m_list.SetCurSel(m_list.GetCount()-1);
}



void CGetMACAddressDlg::OnClickedReturn()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������
	m_list.ResetContent();//���ԭ�п������
}
