
// GetMACAddress.h : PROJECT_NAME Ӧ�ó������ͷ�ļ�
//

#pragma once

#ifndef __AFXWIN_H__
	#error "�ڰ������ļ�֮ǰ������stdafx.h�������� PCH �ļ�"
#endif

#include "resource.h"		// ������


// CGetMACAddressApp:
// �йش����ʵ�֣������ GetMACAddress.cpp
//

class CGetMACAddressApp : public CWinApp
{
public:
	CGetMACAddressApp();

// ��д
public:
	virtual BOOL InitInstance();

// ʵ��

	DECLARE_MESSAGE_MAP()
};

extern CGetMACAddressApp theApp;