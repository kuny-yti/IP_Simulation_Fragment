#ifndef IP_COMMON_H
#define IP_COMMON_H

#include <qglobal.h>
#include <QString>
#include <QStringList>

#if defined(__linux__) || defined(__linux)
#include <arpa/inet.h>
#include <netinet/in.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <unistd.h>
#include <netinet/tcp.h>

#elif defined( __WIN32__ ) || defined( _WIN32 )
#  if _WIN32_WINNT < 0x0600
#    undef _WIN32_WINNT
#    define _WIN32_WINNT 0x0600
#  endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#endif
namespace ICMP {

// ICMP error message types
enum Error
{
    Err_DestUnreachable = 3,  // 无法到达目的地
    Err_SourceQuench    = 4,  //
    Err_Redirect        = 5,  // 重新导向
    Err_TimeExceeded    = 11, // 超过时间
    Err_ParamProblem    = 12, // 参数问题
};

// ICMP request message types
enum Request
{
    Req_Echo          = 8,
    Req_RouterSolicit = 10, // 路由征求
    Req_Timestamp     = 13, // 时间戳
    Req_Info          = 15, // 信息请求-已过时
    Req_AddrMask      = 17  // 地址掩码请求
};

// ICMP reply message types
enum Reply
{
    Rep_Echo         = 0,
    Rep_RouterAdvert = 9,  // 路由广告应答
    Rep_Timestamp    = 14, // 时间戳应答
    Rep_Info         = 16, // 信息应答-已过时
    Rep_AddrMask     = 18, // 地址掩码应答
};

}

namespace IP {

enum Protocol
{
    Protocol_ICMP = 1, // Internet Control Message Protocol
    Protocol_IGMP = 2, //
    Protocol_GGP  = 3,
    Protocol_IP   = 4,
    Protocol_TCP  = 6,
    Protocol_EGP  = 8,
    Protocol_IGP  = 9,
    Protocol_UDP  = 17,
    Protocol_RDP  = 27,
    Protocol_DDP  = 37,
    Protocol_IPv6 = 41,
    Protocol_IDRP = 45,
};

// 4bit的TOS子字段
// 4bit中只能置其中1bit,如果所有4bit均为0是一般服务.
enum ToSSubfield
{
    // Telnet、Rlogin这两个交互应用要求最小的传输时延
    // 最小时延
    ToS_LowDelay = 0x08,        ///< 1 = Low Delay; 0 = Normal Delay
    // FTP文件传输要求最大吞吐量
    // 最大吞吐量
    ToS_HighThroughput = 0x04,  ///< 1 = High Throughput; 0 = Normal Throughput
    // 最高可靠性是指网络管理（SNMP）和路由选择协议
    // 最高可靠性, IPTOS_RELIABILITY
    ToS_HighReliability = 0x02, ///< 1 = High Reliability; 0 = Normal Reliability
    // 用户网络新闻要求最小费用
    // 最小消耗
    ToS_Mincost = 0x01,         ///< 1 = Minimise monetary cost (RFC 1349)

    ToS_Normal = 0x00
};

// 3bit的8个优先级的定义如下：
enum ToSPriority
{
    // 优先级6和7一般保留给网络控制数据使用，如路由。
    // 111--Network Control（网络控制）；
    ToS_NetworkControl = 0x07,

    // 110--Internetwork Control（网间控制）；
    ToS_InternetworkControl = 0x06,

    // 101--Critic（关键, 优先级5推荐给语音数据使用。
    ToS_Critic = 0x05,

    // 100--Flash Override（疾速）,优先级4由视频会议和视频流使用。
    ToS_FlashOverride = 0x04,

    //011--Flash（闪速）,优先级3给语音控制数据使用。
    ToS_Flash = 0x03,

    //010--Immediate（快速）,优先级1和2给数据业务使用。
    ToS_Immediate = 0x02,

    //001--Priority（优先）
    ToS_Priority = 0x01,

    //000--Routine（普通）,优先级0为默认标记值。
    ToS_Routine = 0x00
};

/* IP flags. */
enum IPFlag
{
    IP_Congestion   = 0, /* Flag: "Congestion"		*/
    IP_DontFragment = 2, /* Flag: "Don't Fragment"	*/
    IP_MoreFragment = 4, /* Flag: "More Fragments"	*/
    IP_OffsetPart   = 0x1FFF  /* "Fragment Offset" part	*/
};


static const quint16 DefaultMTU = 0x44; /* RFC 791 */
static const quint8  DefaultVersion = 0x04;
static const quint8  DefaultIHL = 0x05;
static const quint8  DefaultVIHL = (DefaultIHL << 4) | DefaultVersion;
static const quint8  DefaultTTL = 0xef;
static const quint8  DefaultProtocol = Protocol_TCP;
static const quint8  DefaultHeaderLength = DefaultIHL <<2;
static const quint16 DefaultDataMax = (DefaultMTU - DefaultHeaderLength);
static const char *const DefaultSourceAddr = "189.187.1.101";

// IP头部结构
struct Header
{
    // 版本和IP包头长度
    union
    {
        struct
        {
            quint8 version:4;
            quint8 headlen:4;
        };
        quint8 vihl;
    };

    // 服务类型
    union
    {
        struct
        {
            quint8 priority:3;
            quint8 subfield:4;
            quint8 mbz:1;
        };
        quint8 tos;
    };
    // IP包总长度
    quint16 length;
    // 标识符
    quint16 id;

    // 标记和片偏移
    union
    {
        struct
        {
            quint16 flag:3;
            quint16 offset:13;
        };
        quint16 foff;
    };

    // 生存时长
    quint8  ttl;

    // 协议
    quint8  protocol;

    // 校验和
    quint16 checksum;
    // 源地址
    quint32 addrs;
    // 目标地址
    quint32 addrd;
};

// IP 包
struct PackIP
{
    Header head;
    char   data[1];
};

// IP 数据包
struct DataPack
{
    IP::PackIP   *p;

    explicit DataPack(const quint16 MTU = IP::DefaultMTU):
        p(0)
    {
        p = (IP::PackIP *)::malloc(MTU);
        memset(p, 0, MTU);
    }
    explicit DataPack(IP::PackIP *dpk):
        p(0)
    {
        p = (IP::PackIP *)::malloc(dpk->head.length);
        memcpy(p, dpk, dpk->head.length);
    }
    explicit DataPack(IP::Header *hdr):
        p(0)
    {
        p = (IP::PackIP *)::malloc(hdr->length);
        memcpy(p, hdr, hdr->length);
    }
    ~DataPack()
    {
        if (p)
            ::free(p);
    }

    DataPack(const DataPack &dpk):
        p(0)
    {
        *this = dpk;
    }

    DataPack &operator = (const DataPack &dpk)
    {
        if (p)
            free(p);
        p = (IP::PackIP *)::malloc(dpk.head()->length);
        memcpy(p, dpk.pack(), dpk.head()->length);
        return *this;
    }

    PackIP *pack(){return p;}
    Header *head(){return &p->head;}
    char   *data(){return p->data;}
    PackIP *pack()const{return p;}
    Header *head()const{return &p->head;}
    char   *data()const{return p->data;}
};
typedef QList<IP::DataPack> DataPackList;

static const struct
{
    ToSPriority   code;
    const QString str;
}
ToSPriorityLab[] =
{
{ToS_NetworkControl,      "网络控制"},
{ToS_InternetworkControl, "网间控制"},
{ToS_Critic,              "关键"},
{ToS_FlashOverride,       "疾速"},
{ToS_Flash,               "闪速"},
{ToS_Immediate,           "快速"},
{ToS_Priority,            "优先"}
};

static const struct
{
    ToSSubfield    code;
    const QString  str;
}
ToSSubfieldLab[] =
{
{ToS_LowDelay,        "最小时延"},
{ToS_HighThroughput,  "大吞吐量"},
{ToS_HighReliability, "高可靠性"},
{ToS_Mincost,         "最小消耗"}
};

static const struct
{
    IPFlag        code;
    const QString str;
}
IPFlagLab[] =
{
{IP_Congestion, "保留"},
{IP_DontFragment, "不分片"},
{IP_MoreFragment, "多个分片"}
};

static const QStringList HeaderLab =
{
    "版本[4]",
    "头长度[4]",
    "可靠性[5]",
    "优先级[3]",
    "总长度[16]",
    "ID[16]",
    "标志[3]",
    "偏移量[13]",
    "TTL[8]",
    "协议[8]",
    "校验和[16]",
    "源地址[32]",
    "目的地址[32]",
    "数据"
};

quint16 CheckSum(quint16* buffer, int size);

Header MakeHeaderIP();

quint16 HashID(char* v, int len);

}

#endif // IP_COMMON_H
