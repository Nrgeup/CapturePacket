
// CapturePacket.h : PROJECT_NAME Ӧ�ó������ͷ�ļ�
//

#pragma once

#ifndef __AFXWIN_H__
	#error "�ڰ������ļ�֮ǰ������stdafx.h�������� PCH �ļ�"
#endif

#include "resource.h"		// ������
#include "pcap.h"

// CCapturePacketApp:
// �йش����ʵ�֣������ CapturePacket.cpp
//

class CCapturePacketApp : public CWinApp
{
public:
	CCapturePacketApp();

// ��д
public:
	virtual BOOL InitInstance();

// ʵ��

	DECLARE_MESSAGE_MAP()
};

extern CCapturePacketApp theApp;