/*
* Copyright (C) 2016, 2017 SmileOnMyMac, LLC dba Smile. All rights reserved
*
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions
* are met:
* 1. Redistributions of source code must retain the above copyright
*    notice, this list of conditions and the following disclaimer.
* 2. Redistributions in binary form must reproduce the above copyright
*    notice, this list of conditions and the following disclaimer in the
*    documentation and/or other materials provided with the distribution.
*
* THIS SOFTWARE IS PROVIDED BY APPLE INC. ``AS IS'' AND ANY
* EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
* IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
* PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL APPLE INC. OR
* CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
* EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
* PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
* PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
* OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
* OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include "ProxyInformation.h"
#include <wtf/text/WTFString.h>
#include <map>

#pragma comment(lib, "winhttp.lib")

namespace WebCore
{
    // cern type proxies only... (with winhttp)

    ProxyInformation::ProxyInformation()
        : m_handle(nullptr)
    {
        m_handle = WinHttpOpen(nullptr, WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, nullptr, nullptr, 0);
        // if this fails m_handle is nullptr, but we still want to work anyway, so just ignore that.
    }

    ProxyInformation::~ProxyInformation()
    {
        if(m_handle) {
            WinHttpCloseHandle(m_handle);
        }
    }

    static bool isWinHTTPSeperator(wchar_t candidate) {
        // seperators, from msdn sample:
        switch(candidate) {
        case L';':
        case L' ':
        case L'\t':
        case L'\n':
        case L'\v':
        case L'\f':
        case L'\r':
            return true;
        default:
            return false;
        }
    }

    std::vector<String> ProxyInformation::proxiesFor(URL const& url)
    {
        std::vector<String> proxiesToReturn;

        WINHTTP_AUTOPROXY_OPTIONS options = { 0 };
        options.dwAutoDetectFlags = WINHTTP_AUTO_DETECT_TYPE_DHCP | WINHTTP_AUTO_DETECT_TYPE_DNS_A;
        options.dwFlags = WINHTTP_AUTOPROXY_AUTO_DETECT;
        options.lpvReserved = nullptr;
        options.dwReserved = 0;
        // allow proxy result caching by not using authentication by default...
        options.fAutoLogonIfChallenged = FALSE;

        WINHTTP_CURRENT_USER_IE_PROXY_CONFIG config = { 0 };

        // see description at:
        // https://msdn.microsoft.com/en-us/library/windows/desktop/aa383912%28v=vs.85%29.aspx
        String serializedProxyList;
        String serializedBypassList;

        bool isDirect = false;
        bool hasProxy = false;

        if(WinHttpGetIEProxyConfigForCurrentUser(&config)) {
            if(!config.fAutoDetect) {
                if(config.lpszAutoConfigUrl != nullptr) {
                    options.dwAutoDetectFlags = 0; 
                    options.dwFlags = WINHTTP_AUTOPROXY_CONFIG_URL;
                    options.lpszAutoConfigUrl = config.lpszAutoConfigUrl;
                }
                else if(config.lpszProxy) {
                    serializedProxyList = config.lpszProxy;
                    if(config.lpszProxyBypass) {
                        serializedBypassList = config.lpszProxyBypass;
                    }
                    hasProxy = true;
                }
                else {
                    isDirect = true;
                }
            }
        }

        WINHTTP_PROXY_INFO info = { 0 };
        if(!isDirect && !hasProxy && m_handle) {
           URL adjusted = url;
            for(int attempts = 0; attempts < 2;++attempts) {
                if(!WinHttpGetProxyForUrl(m_handle, adjusted.string().charactersWithNullTermination().data(), &options, &info)) {
                    DWORD error = GetLastError();

                    // Wait until we get login failure before setting auto login,
                    // because auto login prevents caching of the PAC script.
                    if(error == ERROR_WINHTTP_LOGIN_FAILURE) {
                        if(WinHttpCloseHandle(m_handle)) {
                            m_handle = WinHttpOpen(nullptr, WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, nullptr, nullptr, 0);

                            if(m_handle) {
                                options.fAutoLogonIfChallenged = TRUE;
                                continue;
                            }
                        }
                        else {
                            m_handle = nullptr;
                        }
                    } else if(error == ERROR_WINHTTP_UNRECOGNIZED_SCHEME) {
						if(adjusted.protocol() == "wss") {
							adjusted.setProtocol(L"https");
							continue;
						}
						else if(adjusted.protocol() == "ws") {
							adjusted.setProtocol(L"http");
							continue;
						}
					}
                }
                else if(info.dwAccessType == WINHTTP_ACCESS_TYPE_NO_PROXY) {
                    isDirect = true;
                }
                else if(info.dwAccessType == WINHTTP_ACCESS_TYPE_NAMED_PROXY) {
                    serializedProxyList = info.lpszProxy;
                    if(info.lpszProxyBypass) {
                        serializedBypassList = info.lpszProxyBypass;
                    }
                    hasProxy = true;
                }

                // always quit the loop, as it only loops if an auto login
                // retry is being done.
                break;
            }
        }

        if(hasProxy) {
            // well, what we have to do is the following:
            // search for our urls host in the bypass list, though it *may*
            // be the case that the proxy bypass list accepts wildcards...
            // yes, it does... (wildcards have to be left-most)...
            // see:  https://msdn.microsoft.com/en-us/library/ms761351%28v=vs.85%29.aspx

            String host = url.host();
            // bypass check algorithm
            // find end of bypass string or seperator
            // check if first character is *
            //   if yes, check that the url's host ends with the remainder
            //   if not, check if the bypass host is <local>
            //      if yes, check that the url's host contains no periods
            //      if not, check that the url is an exact match
            size_t endIndex = notFound;
            for(unsigned bypassIndex = 0; !isDirect && bypassIndex < serializedBypassList.length(); bypassIndex = static_cast<unsigned>(endIndex)) {
                endIndex = serializedBypassList.find(&isWinHTTPSeperator, bypassIndex);

                String bypassHost = (endIndex == notFound)
                    ? serializedBypassList.substringSharingImpl(bypassIndex)
                    : serializedBypassList.substringSharingImpl(bypassIndex, static_cast<unsigned>(endIndex) - bypassIndex);

                if(bypassHost[0] == L'*') {
                    isDirect = host.endsWith(bypassHost.substringSharingImpl(1));
                }
                else if(bypassHost == "<local>") {
                    // According to MSDN, this matches any host without a period in it.
                    isDirect = host.find(L'.') == notFound;
                }
                else {
                    isDirect = host == bypassHost;
                }

                if(endIndex != notFound) {
                    ++endIndex;
                } else {
					break;
				}
            }

        }
        // only determine the proxy to use when the url doesn't
        // match anything in the bypass list
        if(hasProxy && !isDirect) {
            // FROM: https://msdn.microsoft.com/en-us/library/ms761351%28v=vs.85%29.aspx
            // when scheme= is used, the proxy is used for that scheme.

            // make sure the map of proxies also respects the insert ordering

            // Also if the proxy is specified as a url, the default port for that url's scheme
            // is used if is omitted, e.g. https=http://someproxy is equivalent to https=someproxy:80

            // algorithm:
            // break at seperator.
            // determine the proxied scheme (i.e. the scheme =)
            // determine the proxy implementation (i.e the scheme://) part
            // determine the host
            // determine the port (take care to handle IPV6 addresses)

            std::multimap<String, String, decltype(&WTF::codePointCompareLessThan)> proxies(&WTF::codePointCompareLessThan);

            size_t endIndex = notFound;
            for(unsigned proxyIndex = 0; !isDirect && proxyIndex < serializedProxyList.length(); proxyIndex = static_cast<unsigned>(endIndex)) {
                endIndex = serializedProxyList.find(&isWinHTTPSeperator, proxyIndex);

                String proxyDetail = (endIndex == notFound)
                    ? serializedProxyList.substringSharingImpl(proxyIndex)
                    : serializedProxyList.substringSharingImpl(proxyIndex, static_cast<unsigned>(endIndex) - proxyIndex);

                String proxiedScheme;
                auto proxiedSchemeIndex = proxyDetail.find(L'=');
                if(proxiedSchemeIndex != notFound) {
                    proxiedScheme = proxyDetail.substringSharingImpl(0, proxiedSchemeIndex);
                    proxyDetail = proxyDetail.substringSharingImpl(proxiedSchemeIndex + 1);
                }

                String proxyImplementationScheme;
                auto proxyImplementationIndex = proxyDetail.find(L"://");
                if(proxyImplementationIndex != notFound) {
                    proxyImplementationScheme = proxyDetail.substringSharingImpl(0, proxyImplementationIndex);
                }

                auto portDelimiterCandidateIndex = proxyDetail.reverseFind(L":");
                auto endOfIPV6Address = proxyDetail.find(L"]");

                bool hasExplicitPort = portDelimiterCandidateIndex != notFound
                    && portDelimiterCandidateIndex != proxyImplementationIndex
                    && (endOfIPV6Address == notFound || portDelimiterCandidateIndex > endOfIPV6Address);

                // the proxied scheme for socks is a bit different,
                // it means that for any connections that don't fall into
                // any other schemes, use the socks 4 specified proxy.
                if(proxiedScheme == "socks") {
                    // need to correct it to use the right url...
                    if(proxyImplementationScheme.isEmpty()) {
                        // WinHTTP only supports socks4 proxies, so we use that as the url...
                        proxies.emplace(proxiedScheme, L"socks4://" + proxyDetail);
                    }
                    else {
                        // assume that it was done correctly.
                        proxies.emplace(proxiedScheme, proxyDetail);
                    }

                }
                else if(hasExplicitPort) {
                    proxies.emplace(proxiedScheme, proxyDetail);
                }
                else if(proxyImplementationScheme == "https") {
                    // need to specify the port ourselves, as the defaults differ between WinHTTP
                    // and CURL.
                    proxies.emplace(proxiedScheme, proxyDetail + L":443");
                }
                else {
                    proxies.emplace(proxiedScheme, proxyDetail + L":80");
                }

                if(endIndex != notFound) {
                    ++endIndex;
                } else {
					break;
				}
            }

            // okay we now have a map of the available proxies.
            // let's query from our url to determine what we want to use
            decltype(proxies)::const_iterator match_iter;
            decltype(proxies)::const_iterator match_end;

			String protocol = url.protocol().toString();
			tie(match_iter, match_end) = proxies.equal_range(protocol);

            for(; match_iter != match_end; ++match_iter) {
                proxiesToReturn.emplace_back(match_iter->second);
            }

            if(proxiesToReturn.empty() && url.protocol() == "wss") {
                tie(match_iter, match_end) = proxies.equal_range(L"https");

                for(; match_iter != match_end; ++match_iter) {
                    proxiesToReturn.emplace_back(match_iter->second);
                }
            }

            if(proxiesToReturn.empty() && url.protocol() == "ws") {
                tie(match_iter, match_end) = proxies.equal_range(L"http");

                for(; match_iter != match_end; ++match_iter) {
                    proxiesToReturn.emplace_back(match_iter->second);
                }
            }

            // Special case for when socks is specified, rather than actually being
            // a "per-scheme" proxy in it's own right, it is instead a fallback option,
            // but one that specifies a socks proxy:
            // https://chromium.googlesource.com/chromium/src/net/+/master/proxy/proxy_config.cc
            if(proxiesToReturn.empty()) {
                tie(match_iter, match_end) = proxies.equal_range(L"socks");

                for(; match_iter != match_end; ++match_iter) {
                    // N.B. the scheme is fixed up when the proxy list is parsed.
                    proxiesToReturn.emplace_back(match_iter->second);
                }
            }

            // fallback proxies
            tie(match_iter, match_end) = proxies.equal_range(L"");

            for(; match_iter != match_end; ++match_iter) {
                proxiesToReturn.emplace_back(match_iter->second);
            }
        }

        // cleanup
        if(info.lpszProxy) {
            GlobalFree(info.lpszProxy);
        }

        if(info.lpszProxyBypass) {
            GlobalFree(info.lpszProxyBypass);
        }

        if(config.lpszProxy) {
            GlobalFree(config.lpszProxy);
        }

        if(config.lpszProxyBypass) {
            GlobalFree(config.lpszProxyBypass);
        }

        if(config.lpszAutoConfigUrl) {
            GlobalFree(config.lpszAutoConfigUrl);
        }

        return proxiesToReturn;
    }
}