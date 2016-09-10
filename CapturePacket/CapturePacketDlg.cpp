
// CapturePacketDlg.cpp : ʵ���ļ�
//

#include "stdafx.h"
#include "CapturePacket.h"
#include "CapturePacketDlg.h"
#include "afxdialogex.h"
#include "pcap.h"

	

#ifdef _DEBUG
#define new DEBUG_NEW
#define WM_PACKET WM_USER+1
#endif

//ȫ�ֱ���
pcap_t* afx_adhandle;         //��ǰ�򿪵�����ӿ�
//pcap_pkthdr *afx_header;
struct pcap_pkthdr *afx_header;
const u_char *afx_pkt_data; 




// ����Ӧ�ó��򡰹��ڡ��˵���� CAboutDlg �Ի���

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
};

CAboutDlg::CAboutDlg() : CDialogEx(CAboutDlg::IDD)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
END_MESSAGE_MAP()




// CCapturePacketDlg �Ի���



CCapturePacketDlg::CCapturePacketDlg(CWnd* pParent /*=NULL*/)
	: CDialogEx(CCapturePacketDlg::IDD, pParent)
	, m_state(false)
	, m_Capturer(NULL)
	, m_select(_T(""))
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
	
	//��ñ������豸�б�
	char  errbuf[PCAP_ERRBUF_SIZE];	//������Ϣ������
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, 	//��ȡ�����Ľӿ��豸
			NULL,			       //������֤
			&m_alldevs, 		       //ָ���豸�б��ײ�
			errbuf			      //������Ϣ���滺����
			) == -1)
	{	MessageBox(L"��ȡ�����豸�б�ʧ�ܣ�"+CString(errbuf),MB_OK);/*������*/}
	m_now=m_alldevs;
}

void CCapturePacketDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_Interface_LIST, mc_Interface);
	DDX_Control(pDX, IDC_Message_LIST, mc_Message);
	DDX_Control(pDX, IDC_CATCH, m_catch);
	DDX_Control(pDX, IDC_STOP, m_stop);
	DDX_Control(pDX, IDC_RETURN, m_return);
	DDX_Control(pDX, IDC_LIST, m_list);
	//  DDX_Text(pDX, IDC_EDIT, m_select);
	//  DDV_MinMaxInt(pDX, m_select, 0, 100000);
	DDX_Control(pDX, IDC_EDIT, mc_select);
	DDX_Text(pDX, IDC_EDIT, m_select);
}

BEGIN_MESSAGE_MAP(CCapturePacketDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
//	ON_NOTIFY(NM_THEMECHANGED, IDC_Interface_LIST, &CCapturePacketDlg::OnNMThemeChangedInterfaceList)
ON_WM_CLOSE()
ON_LBN_SELCHANGE(IDC_LIST, &CCapturePacketDlg::OnLbnSelchangeList)
//ON_LBN_SETFOCUS(IDC_Interface_LIST, &CCapturePacketDlg::OnLbnSetfocusInterfaceList)
//ON_LBN_SETFOCUS(IDC_Interface_LIST, &CCapturePacketDlg::OnLbnSetfocusInterfaceList)
ON_LBN_SELCHANGE(IDC_Interface_LIST, &CCapturePacketDlg::OnSelchangeInterfaceList)
ON_BN_CLICKED(IDC_CATCH, &CCapturePacketDlg::OnClickedCatch)
ON_BN_CLICKED(IDC_RETURN, &CCapturePacketDlg::OnClickedReturn)
ON_BN_CLICKED(IDC_STOP, &CCapturePacketDlg::OnClickedStop)
ON_MESSAGE(WM_PACKET,OnPacket)		//������Ϣӳ��
END_MESSAGE_MAP()


// CCapturePacketDlg ��Ϣ�������

BOOL CCapturePacketDlg::OnInitDialog()
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

	ShowWindow(SW_MINIMIZE);

	// TODO: �ڴ���Ӷ���ĳ�ʼ������
	mc_Interface.SetHorizontalExtent(600);
	mc_Message.SetHorizontalExtent(600);
	m_list.SetHorizontalExtent(2000);

	//��ȡ�����ӿں�IP��ַ             
	pcap_if_t	*d;		//ָ���豸�����ײ���ָ��
	
	for(d= m_alldevs; d != NULL; d= d->next)      //��ʾ�ӿ��б�
	{
		mc_Interface.AddString(CString(d->name));	//����d->name��ȡ������ӿ��豸������
	}

	Update_Message();//������Ϣ
	mc_Interface.SetCurSel(0);
	m_stop.EnableWindow(FALSE);	//��ʼʹ��ֹͣ���񡱰�ťʧЧ
	m_return.EnableWindow(FALSE);	//��ʼʹ�����ء���ťʧЧ

	return TRUE;  // ���ǽ��������õ��ؼ������򷵻� TRUE
}

void CCapturePacketDlg::OnSysCommand(UINT nID, LPARAM lParam)
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

void CCapturePacketDlg::OnPaint()
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
HCURSOR CCapturePacketDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}


void CCapturePacketDlg::OnClose()
{
	// TODO: �ڴ������Ϣ�����������/�����Ĭ��ֵ
	pcap_freealldevs(m_alldevs); //�ͷ��豸�б�
	CDialogEx::OnClose();
}


void CCapturePacketDlg::OnLbnSelchangeList()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������
	
}


void CCapturePacketDlg::OnSelchangeInterfaceList()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������
	if(!m_state){
		int N=mc_Interface.GetCurSel();//��ȡlistbox��ѡ�е��е���Ŀ
		m_now=m_alldevs;
		while(N--)
		{
			m_now=m_now->next;
		}
		Update_Message();
	}
}

//���²���ӿڵ���ϸ��Ϣ��
void CCapturePacketDlg::Update_Message(void)
{
	//���²���ӿڵ���ϸ��Ϣ
	mc_Message.ResetContent();//���ԭ�п������
	mc_Message.AddString(CString(m_now->name));			//��ʾ������ӿ��豸������
	mc_Message.AddString(CString(m_now->description));	//��ʾ������ӿ��豸��������Ϣ

	pcap_addr_t	*a;
	a=m_now->addresses;
	for(a=m_now->addresses; a!=NULL; a=a->next){
		if(a->addr->sa_family==AF_INET){  //�жϸõ�ַ�Ƿ�IP��ַ
			CString output;
			DWORD temp_IP;
			
			temp_IP=ntohl(((struct sockaddr_in *)a->addr)->sin_addr.s_addr);  //��ʾIP��ַ
			output.Format(L"IP��ַ��%s",long2ip(temp_IP));
			mc_Message.AddString(output);

			
			m_this_netmask=ntohl(((struct sockaddr_in *)a->netmask)->sin_addr.s_addr);  //��ʾ��ַ����
			output.Format(L"��ַ���룺%s",long2ip(m_this_netmask));
			mc_Message.AddString(output);

			
			temp_IP=ntohl(((struct sockaddr_in *)a->broadaddr)->sin_addr.s_addr);  //��ʾ�㲥��ַ
			output.Format(L"�㲥��ַ��%s",long2ip(temp_IP));
			mc_Message.AddString(output);
			
		}
	}

	return void();
}



void CCapturePacketDlg::OnClickedCatch()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������

	m_state=true;	//���Ƿ���벶��״̬��Ǵ�
	mc_Interface.EnableWindow(FALSE);
	mc_select.EnableWindow(FALSE);
	//������ť״̬
	m_catch.EnableWindow(FALSE);
	m_stop.EnableWindow(TRUE);
	m_return.EnableWindow(FALSE);

	m_list.ResetContent();//���ԭ�п������

	//�����������߳�
	m_Capturer=AfxBeginThread((AFX_THREADPROC)Capturer,NULL,THREAD_PRIORITY_NORMAL);  
	if(m_Capturer ==NULL ){
		AfxMessageBox(L"�����������ݰ��߳�ʧ��!",MB_OK|MB_ICONERROR);
		return ;
	}
	else   /*��ѡ������� */
	{
		m_list.AddString(L"--------------------------------------------------------------------------------------------------------------------------------------------------------");
		m_list.AddString(L"����"+CString(m_now->description)+L" ��ʼ��");
		m_list.AddString(L"--------------------------------------------------------------------------------------------------------------------------------------------------------");
	}
	UpdateData(true);
}

void CCapturePacketDlg::OnClickedStop()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������

	//������ť״̬
	m_catch.EnableWindow(TRUE);
	m_stop.EnableWindow(FALSE);
	m_return.EnableWindow(TRUE);
	mc_select.EnableWindow(TRUE);
	m_state=false;
}


void CCapturePacketDlg::OnClickedReturn()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������

	//������ť״̬
	m_state=false;
	mc_Interface.EnableWindow(TRUE);
	m_catch.EnableWindow(TRUE);
	m_stop.EnableWindow(FALSE);
	m_return.EnableWindow(FALSE);
	mc_select.EnableWindow(TRUE);
	m_list.ResetContent();//���ԭ�п������
	m_select=L"";
	UpdateData(false);
}


//���ݰ����������߳�
UINT Capturer(LPVOID pParm)
{
	CCapturePacketDlg* dlg = (CCapturePacketDlg*)theApp.m_pMainWnd; //��ȡ�Ի�����

	char errbuff[1000];
	memset(errbuff,0,sizeof(errbuff));

	if ((afx_adhandle= pcap_open(dlg->m_now->name,	// �豸����
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

	
	
	
	if(!dlg->m_select.IsEmpty())
	{
		struct bpf_program fcode;     //pcap_compile�����õĽṹ��
		//��ʽ������ܹ����������������͵ĵͲ���ֽ���
		char str[20];
		memset(str,0,sizeof(str));
		for(int i=0;i<dlg->m_select.GetLength();i++)
			str[i]=dlg->m_select[i];

		if(pcap_compile(afx_adhandle,&fcode,str,1,dlg->m_this_netmask)<0)
			AfxMessageBox(L"���˳�������!",MB_OK|MB_ICONERROR);
		if (pcap_setfilter(afx_adhandle, &fcode)<0)
			AfxMessageBox(L"���˳�������!",MB_OK|MB_ICONERROR);
	}
	
	//����pcap_next_ex�����������ݰ�
	/* �˴�ѭ������ pcap_next_ex���������ݱ�*/ 
	int res;
	while(dlg->m_state&&(res = pcap_next_ex(afx_adhandle,&afx_header,&afx_pkt_data))>=0){
		if(res==0)  //��ʱ���
			continue;
		//���ô��ڵ�PostMessage����������Ϣ
		AfxGetApp()->m_pMainWnd->PostMessage(WM_PACKET,0,0);
		//memset(afx_header,0,sizeof(afx_header));
		//memset(afx_pkt_data,0,sizeof(afx_pkt_data));
	}
	if(res==-1)  //��ȡ���ݰ�����
	{
		AfxGetApp()->m_pMainWnd->PostMessage(WM_PACKET,1,1);
		dlg->m_state=false;
	}

	return 0;
}


//��Ϣ������
LRESULT CCapturePacketDlg::OnPacket(WPARAM wParam, LPARAM lParam)
{
	/*����*/	//�����񵽵����ݰ�
	if(wParam==0&&lParam==0&&m_state==true)
	{

		//��ʾĿ�ĵ�ַ��Դ��ַ��֡����	

		Data_t	* IPPacket;
		ULONG		SourceIP,DestinationIP;
		IPPacket = (Data_t *) afx_pkt_data;
		SourceIP = ntohl(IPPacket->IPHeader.SrcIP);
		DestinationIP = ntohl(IPPacket->IPHeader.DstIP);
	

		WORD Kind = ntohs(IPPacket->FrameHeader.FrameType);
		WORD Len = afx_header->caplen;
		
		
		time_t time = afx_header->ts.tv_sec;
		struct tm *ltime=new struct tm;
		localtime_s(ltime,&time);
		char timestr[16];
		strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);

		CString TIME(timestr);

		CString output1,output2;
		//CString TIME=CTime::GetCurrentTime().Format("%H:%M:%S");
		output1.Format(L"%s , len: %d",TIME,Len);
		output2.Format(L"Ŀ�ĵ�ַ�� %s     Դ��ַ�� %s     ֡���ͣ�0x%04X",char2mac(IPPacket->FrameHeader.DesMAC), char2mac(IPPacket->FrameHeader.SrcMAC) ,Kind);

		//������趨�����һ��
		m_list.AddString(output1);
		m_list.AddString(output2);
		int num=m_list.GetCount();
		m_list.SetCurSel(num-1);
	}
	else
	{
		m_list.AddString(L"��ȡ���ݰ�������");
	}
	m_list.AddString(L"--------------------------------------------------------------------------------------------------------------------------------------------------------");
	return 0;
}


/* ��char*���͵�MAC��ַת�����ַ������͵� */
CString CCapturePacketDlg::char2mac(BYTE* MAC)
{
	CString ans;
	ans.Format(L"%02X-%02X-%02X-%02X-%02X-%02X",int(MAC[0]),int(MAC[1]),int(MAC[2]),int(MAC[3]),int(MAC[4]),int(MAC[5]));
	return ans;
}

/* ���������͵�IP��ַת�����ַ������͵� */
CString CCapturePacketDlg::long2ip(DWORD in)
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
DWORD CCapturePacketDlg::ip2long (CString in)
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