
// CapturePacketDlg.h : ͷ�ļ�
//

#pragma once
#include "pcap.h"
#include "afxwin.h"

// CCapturePacketDlg �Ի���
class CCapturePacketDlg : public CDialogEx
{
// ����
public:
	CCapturePacketDlg(CWnd* pParent = NULL);	// ��׼���캯��

// �Ի�������
	enum { IDD = IDD_CAPTUREPACKET_DIALOG };

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
	afx_msg LRESULT OnPacket(WPARAM wParam, LPARAM lParam);

public:
	CListBox mc_Interface;		//�������е���̫���ӿ�
	CListBox mc_Message;		//����ӿڵ���ϸ��Ϣ
	CButton m_catch;			//�����İ�ť
	CButton m_stop;				//ֹͣ�����İ�ť
	CButton m_return;			//���ذ�ť
	CListBox m_list;			//��������־
	pcap_if_t* m_alldevs;		// ָ���豸�б��ײ���ָ��	
	afx_msg void OnClose();
	afx_msg void OnLbnSelchangeList();
	pcap_if_t* m_now;
	afx_msg void OnSelchangeInterfaceList();
	void Update_Message(void);	//���²���ӿڵ���ϸ��Ϣ��
	bool m_state;				//���ڱ���Ƿ���벶��״̬
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




//ȫ�ֺ���
UINT Capturer(LPVOID pParm);//�̺߳����Ķ���


#pragma pack(1)		//�����ֽڶ��뷽ʽ
typedef struct FrameHeader_t  {	//֡�ײ�
    BYTE	DesMAC[6];	// Ŀ�ĵ�ַ
    BYTE 	SrcMAC[6];	// Դ��ַ
    WORD	FrameType;	// ֡����
} FrameHeader_t;
typedef struct IPHeader_t {		//IP�ײ�
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
typedef struct Data_t {	//����֡�ײ���IP�ײ������ݰ�
	FrameHeader_t	FrameHeader;
	IPHeader_t		IPHeader;
} Data_t;
#pragma pack()	//�ָ�ȱʡ���뷽ʽ
