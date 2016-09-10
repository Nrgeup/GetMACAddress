
// GetMACAddressDlg.h : ͷ�ļ�
//

#pragma once
#include "pcap.h"
#include "afxwin.h"


// CGetMACAddressDlg �Ի���
class CGetMACAddressDlg : public CDialogEx
{
// ����
public:
	CGetMACAddressDlg(CWnd* pParent = NULL);	// ��׼���캯��

// �Ի�������
	enum { IDD = IDD_GETMACADDRESS_DIALOG };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV ֧��


// ʵ��
protected:
	HICON m_hIcon;

	// ���ɵ���Ϣӳ�亯��
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	CListBox mc_Message;	//����ӿڵ���ϸ��Ϣ
	CListBox m_list;
	pcap_if_t* m_alldevs;		//ָ���豸�б��ײ���ָ��	
	pcap_if_t* m_selectdevs;	//��ǰѡ����豸�б��ָ��	
	afx_msg void OnClose();
	int SendARP(BYTE* SrcMAC,BYTE* SendHa,DWORD SendIp,DWORD RecvIp);		//����ARP������
	DWORD m_this_ip;		//����IP��ַ
	BYTE  m_this_mac[6];	//���������ַ
	DWORD m_IP;				//��ѯ��IP��ַ
	BYTE  m_MAC[6];			//��ѯ��õ������ַ
	DWORD m_this_broad;		//�����㲥��ַ
	DWORD m_this_netmask;	//������������
	
	DWORD ip2long (CString in);	/* ���ַ������͵�IP��ַת�����������͵� */
	CString long2ip(DWORD in);	/* ���������͵�IP��ַת�����ַ������͵� */
	CWinThread* m_Capturer;		/*�������߳�*/
	int GetSelfMac(void);		/*��ȡ�Լ�������MAC��ַ*/
	
	CString  char2mac(BYTE* MAC);/* ��char*���͵�MAC��ַת�����ַ������͵� */
	bool  m_if_get_this_mac;		//����Ƿ��Ѿ���ñ���MAC��ַ
	bool  m_get_state;				//����Ƿ��Ѿ���������MAC��ַ
	afx_msg void OnIpnFieldchangedIpaddress1(NMHDR *pNMHDR, LRESULT *pResult);
	afx_msg void OnBnClickedOk();
	
	CButton mc_get;
	CButton mc_return;
	afx_msg void OnBnClickedGet();
	afx_msg void OnClickedReturn();
};


//ȫ�ֺ���
UINT Capturer(LPVOID pParm);//�̺߳����Ķ���

#pragma pack(1)		//�����ֽڶ��뷽ʽ
typedef struct FrameHeader_t  {	//֡�ײ�
    BYTE	DesMAC[6];		// Ŀ�ĵ�ַ
    BYTE	SrcMAC[6];		// Դ��ַ
    WORD	FrameType;		// ֡����
} FrameHeader_t;
typedef struct ARPFrame_t {		//ARP֡
	FrameHeader_t	FrameHeader;	//֡ͷ���ṹ��
	WORD			HardwareType;	//Ӳ������
	WORD			ProtocolType;	//Э������
	BYTE			HLen;			//Ӳ����ַ����
	BYTE			PLen;			//Э���ַ����
	WORD			Operation;		//�����ֶ�
	BYTE			SendHa[6];		//Դmac��ַ
	DWORD			SendIP;			//Դip��ַ
	BYTE			RecvHa[6];		//Ŀ��mac��ַ
	DWORD			RecvIP;			//Ŀ��ip��ַ
} ARPFrame_t;
#pragma pack()		//�ָ�ȱʡ���뷽ʽ
