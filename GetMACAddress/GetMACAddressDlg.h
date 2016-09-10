
// GetMACAddressDlg.h : 头文件
//

#pragma once
#include "pcap.h"
#include "afxwin.h"


// CGetMACAddressDlg 对话框
class CGetMACAddressDlg : public CDialogEx
{
// 构造
public:
	CGetMACAddressDlg(CWnd* pParent = NULL);	// 标准构造函数

// 对话框数据
	enum { IDD = IDD_GETMACADDRESS_DIALOG };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 支持


// 实现
protected:
	HICON m_hIcon;

	// 生成的消息映射函数
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	CListBox mc_Message;	//捕获接口的详细信息
	CListBox m_list;
	pcap_if_t* m_alldevs;		//指向设备列表首部的指针	
	pcap_if_t* m_selectdevs;	//当前选择的设备列表的指针	
	afx_msg void OnClose();
	int SendARP(BYTE* SrcMAC,BYTE* SendHa,DWORD SendIp,DWORD RecvIp);		//发送ARP请求函数
	DWORD m_this_ip;		//本机IP地址
	BYTE  m_this_mac[6];	//本机物理地址
	DWORD m_IP;				//查询的IP地址
	BYTE  m_MAC[6];			//查询获得的物理地址
	DWORD m_this_broad;		//本机广播地址
	DWORD m_this_netmask;	//本机子网掩码
	
	DWORD ip2long (CString in);	/* 将字符串类型的IP地址转换成数字类型的 */
	CString long2ip(DWORD in);	/* 将数字类型的IP地址转换成字符串类型的 */
	CWinThread* m_Capturer;		/*工作者线程*/
	int GetSelfMac(void);		/*获取自己主机的MAC地址*/
	
	CString  char2mac(BYTE* MAC);/* 将char*类型的MAC地址转换成字符串类型的 */
	bool  m_if_get_this_mac;		//标记是否已经获得本机MAC地址
	bool  m_get_state;				//标记是否已经获得请求的MAC地址
	afx_msg void OnIpnFieldchangedIpaddress1(NMHDR *pNMHDR, LRESULT *pResult);
	afx_msg void OnBnClickedOk();
	
	CButton mc_get;
	CButton mc_return;
	afx_msg void OnBnClickedGet();
	afx_msg void OnClickedReturn();
};


//全局函数
UINT Capturer(LPVOID pParm);//线程函数的定义

#pragma pack(1)		//进入字节对齐方式
typedef struct FrameHeader_t  {	//帧首部
    BYTE	DesMAC[6];		// 目的地址
    BYTE	SrcMAC[6];		// 源地址
    WORD	FrameType;		// 帧类型
} FrameHeader_t;
typedef struct ARPFrame_t {		//ARP帧
	FrameHeader_t	FrameHeader;	//帧头部结构体
	WORD			HardwareType;	//硬件类型
	WORD			ProtocolType;	//协议类型
	BYTE			HLen;			//硬件地址长度
	BYTE			PLen;			//协议地址长度
	WORD			Operation;		//操作字段
	BYTE			SendHa[6];		//源mac地址
	DWORD			SendIP;			//源ip地址
	BYTE			RecvHa[6];		//目的mac地址
	DWORD			RecvIP;			//目的ip地址
} ARPFrame_t;
#pragma pack()		//恢复缺省对齐方式
