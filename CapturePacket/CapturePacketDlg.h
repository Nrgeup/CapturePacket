
// CapturePacketDlg.h : 头文件
//

#pragma once
#include "pcap.h"
#include "afxwin.h"

// CCapturePacketDlg 对话框
class CCapturePacketDlg : public CDialogEx
{
// 构造
public:
	CCapturePacketDlg(CWnd* pParent = NULL);	// 标准构造函数

// 对话框数据
	enum { IDD = IDD_CAPTUREPACKET_DIALOG };

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
	afx_msg LRESULT OnPacket(WPARAM wParam, LPARAM lParam);

public:
	CListBox mc_Interface;		//本机具有的以太网接口
	CListBox mc_Message;		//捕获接口的详细信息
	CButton m_catch;			//捕获报文按钮
	CButton m_stop;				//停止捕获报文按钮
	CButton m_return;			//返回按钮
	CListBox m_list;			//捕获工作日志
	pcap_if_t* m_alldevs;		// 指向设备列表首部的指针	
	afx_msg void OnClose();
	afx_msg void OnLbnSelchangeList();
	pcap_if_t* m_now;
	afx_msg void OnSelchangeInterfaceList();
	void Update_Message(void);	//更新捕获接口的详细信息框
	bool m_state;				//用于标记是否进入捕获状态
	afx_msg void OnClickedCatch();
	afx_msg void OnClickedReturn();
	afx_msg void OnClickedStop();
	CWinThread* m_Capturer;
	CString char2mac(BYTE* MAC);
	
	CEdit mc_select;
	CString m_select;
	DWORD m_this_netmask;
	CString long2ip(DWORD in);
	DWORD ip2long (CString in);
};




//全局函数
UINT Capturer(LPVOID pParm);//线程函数的定义


#pragma pack(1)		//进入字节对齐方式
typedef struct FrameHeader_t  {	//帧首部
    BYTE	DesMAC[6];	// 目的地址
    BYTE 	SrcMAC[6];	// 源地址
    WORD	FrameType;	// 帧类型
} FrameHeader_t;
typedef struct IPHeader_t {		//IP首部
	BYTE	Ver_HLen;
	BYTE	TOS;
	WORD	TotalLen;
	WORD	ID;
	WORD	Flag_Segment;
	BYTE	TTL;
	BYTE	Protocol;
	WORD	Checksum;
	ULONG	SrcIP;
	ULONG	DstIP;
} IPHeader_t;
typedef struct Data_t {	//包含帧首部和IP首部的数据包
	FrameHeader_t	FrameHeader;
	IPHeader_t		IPHeader;
} Data_t;
#pragma pack()	//恢复缺省对齐方式
