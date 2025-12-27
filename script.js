document.addEventListener('DOMContentLoaded', () => {
    const inputLinksEl = document.getElementById('inputLinks');
    const configNameEl = document.getElementById('configName');
    const convertBtn = document.getElementById('convertBtn');
    const outputConfigEl = document.getElementById('outputConfig');
    const copyBtn = document.getElementById('copyBtn');
    const downloadBtn = document.getElementById('downloadBtn');
    const saveConfigBtn = document.getElementById('saveConfigBtn');
    const savedConfigsListEl = document.getElementById('savedConfigsList');

    let currentGeneratedConfig = null;

    convertBtn.addEventListener('click', handleConversion);
    copyBtn.addEventListener('click', copyConfig);
    downloadBtn.addEventListener('click', downloadConfig);
    saveConfigBtn.addEventListener('click', saveCurrentConfig);

    loadSavedConfigs();

    const firstActiveTabButton = document.querySelector('.tab-button.active');
    if (firstActiveTabButton) {
        const tabNameMatch = firstActiveTabButton.getAttribute('onclick').match(/'([^']+)'/);
        if (tabNameMatch && tabNameMatch[1]) {
            openTab({ currentTarget: firstActiveTabButton }, tabNameMatch[1]);
        }
    }

    async function handleConversion() {
        const linksText = inputLinksEl.value.trim();
        if (!linksText) {
            alert('Например, пожалуйста, введите хотя бы одну прокси-ссылку или ссылку для подписки.');
            return;
        }

        outputConfigEl.value = 'Обработка данных, пожалуйста, подождите...';
        convertBtn.disabled = true;
        convertBtn.textContent = 'Преобразование...';
        copyBtn.disabled = true;
        downloadBtn.disabled = true;
        saveConfigBtn.disabled = true;

        try {
            const lines = linksText.split('\n').map(line => line.trim()).filter(line => line);
            let allOutbounds = [];

            for (const line of lines) {
                if (line.startsWith('http://') || line.startsWith('https://')) {
                    try {
                        const subOutbounds = await processSubscriptionLink(line);
                        allOutbounds.push(...subOutbounds.filter(ob => ob !== null));
                    } catch (error) {
                        console.error(`Error processing subscription ${line}:`, error);
                        alert(`Ошибка обработки ссылки подписки ${line}: ${error.message}`);
                    }
                } else {
                    try {
                        const outbound = parseProxyLink(line);
                        if (outbound) {
                            allOutbounds.push(outbound);
                        }
                    } catch (error) {
                        console.error(`Error processing link ${line}:`, error.message);
                    }
                }
            }

            if (allOutbounds.length > 0) {
                currentGeneratedConfig = generateFullSingBoxConfig(allOutbounds);
                outputConfigEl.value = JSON.stringify(currentGeneratedConfig, null, 2);
                copyBtn.disabled = false;
                downloadBtn.disabled = false;
                saveConfigBtn.disabled = false;
            } else {
                outputConfigEl.value = 'Не удалось найти подходящий прокси-сервер для конвертации, или произошла ошибка при обработке подписок...';
            }

        } catch (error) {
            console.error('General conversion error:', error);
            outputConfigEl.value = `خطای کلی در تبدیل: ${error.message}`;
        } finally {
            convertBtn.disabled = false;
            convertBtn.textContent = 'Преобразовать в конфигурацию Sing-Box';
        }
    }

    async function processSubscriptionLink(url) {
        const outbounds = [];
        try {
            const response = await fetch(`https://api.allorigins.win/get?url=${encodeURIComponent(url)}`);
            if (!response.ok) {
                let errorMsg = `Network response was not ok for subscription: ${response.status}`;
                try {
                    const errorData = await response.json();
                    errorMsg += ` - ${errorData?.contents || response.statusText}`;
                } catch (e) { /* ignore */ }
                throw new Error(errorMsg);
            }
            const data = await response.json();
            if (!data.contents) {
                throw new Error('CORS proxy did not return content.');
            }
            const decodedContent = atob(data.contents);
            const links = decodedContent.split('\n').map(link => link.trim()).filter(link => link);

            for (const link of links) {
                try {
                    const outbound = parseProxyLink(link);
                    if (outbound) {
                        outbounds.push(outbound);
                    }
                } catch (e) {
                    console.warn(`Skipping invalid link in subscription: "${link.substring(0,30)}..."`, e.message);
                }
            }
        } catch (error) {
            console.error(`Failed to fetch or parse subscription from ${url}:`, error);
            throw new Error(`Получить или обработать подписку ${url} Попытка оказалась безуспешной: ${error.message}`);
        }
        return outbounds;
    }
    
    function sanitizeTag(tag) {
        if (typeof tag !== 'string') tag = String(tag);
        let sanitized = tag.replace(/[^\p{L}\p{N}\p{Z}\p{P}_ -]/gu, '').trim();
        sanitized = sanitized.replace(/\s+/g, '_').replace(/[|()[\]{}:;"'<>,.?/~`!@#$%^&*+=]/g, '_');
        sanitized = sanitized.replace(/__+/g, '_');
        sanitized = sanitized.replace(/^_+|_+$/g, '');
        return sanitized.slice(0, 50) || `proxy_tag_${Date.now()%10000}`;
    }

    function parseProxyLink(link) {
        if (link.startsWith('vless://')) {
            return parseVlessLink(link);
        } else if (link.startsWith('vmess://')) {
            return parseVmessLink(link);
        } else if (link.startsWith('hysteria2://') || link.startsWith('hy2://')) {
            return parseHysteria2Link(link);
        } else {
            console.warn(`Unsupported link format: ${link.substring(0,30)}...`);
            return null;
        }
    }

    function parseVlessLink(link) {
        const url = new URL(link);
        const params = new URLSearchParams(url.search);
        const remark = decodeURIComponent(url.hash.substring(1)) || `vless_${url.hostname}_${url.port || 'default'}`;
        const tag = sanitizeTag(remark);

        const security = params.get('security');
        const encryption = params.get('encryption');
        const transportTypeParam = params.get('type'); // Renamed to avoid conflict with outbound.type

        const outbound = {
            type: "vless",
            tag: tag,
            server: url.hostname,
            server_port: parseInt(url.port) || (security === 'tls' || security === 'reality' ? 443 : 80),
            uuid: url.username,
        };
        
        if (security === 'tls' || security === 'reality') {
            outbound.tls = {
                enabled: true,
                server_name: params.get('sni') || params.get('host') || url.hostname,
                utls: {
                    enabled: true,
                    fingerprint: params.get('fp') || "chrome"
                }
            };
            if (security === 'reality') {
                outbound.tls.reality = {
                    enabled: true,
                    public_key: params.get('pbk'),
                    short_id: params.get('sid') || ""
                };
            }
        } else if ((!security || security === "" || security === "none") && encryption === "none") {
            outbound.encryption = "none";
        }

        const flow = params.get('flow');
        if (flow && (security === 'tls' || security === 'reality')) {
            outbound.flow = flow;
        }
        
        // Transport Protocol: Crucial Change Here!
        // Only add transport object if it's NOT plain TCP.
        if (transportTypeParam && transportTypeParam !== 'tcp') {
            outbound.transport = { type: transportTypeParam };
            if (transportTypeParam === 'ws') {
                outbound.transport.path = params.get('path') || "/";
                outbound.transport.headers = { Host: params.get('host') || url.hostname };
            } else if (transportTypeParam === 'grpc') {
                outbound.transport.service_name = params.get('serviceName') || "";
            }
            // Add other transport types like 'h2', 'quic' if needed.
        }
        // If transportTypeParam is 'tcp' or not specified, DO NOT add the transport object.
        // Sing-box assumes TCP if no transport object is present for VLESS/VMess.
        
        return outbound;
    }

    function parseVmessLink(link) {
        const base64Config = link.substring(8);
        let vmessConfig;
        try {
            const configStr = atob(base64Config);
            vmessConfig = JSON.parse(configStr);
        } catch (e) {
            console.error("Error decoding or parsing VMess link:", e, "Input:", link);
            throw new Error(`Invalid VMess link: ${link.substring(0, 25)}...`);
        }

        const remark = vmessConfig.ps || `vmess_${vmessConfig.add}_${vmessConfig.port || 'default'}`;
        const tag = sanitizeTag(remark);

        const outbound = {
            type: "vmess",
            tag: tag,
            server: vmessConfig.add,
            server_port: parseInt(vmessConfig.port),
            uuid: vmessConfig.id,
            alter_id: parseInt(vmessConfig.aid) || 0,
            security: vmessConfig.scy || vmessConfig.security || "auto",
        };

        if (vmessConfig.tls === 'tls' || vmessConfig.tls === 'reality' || ((vmessConfig.net === 'ws' || vmessConfig.net === 'h2') && (vmessConfig.host || vmessConfig.sni))) {
             outbound.tls = {
                enabled: true,
                server_name: vmessConfig.sni || vmessConfig.host || vmessConfig.add,
                utls: {
                    enabled: true,
                    fingerprint: vmessConfig.fp || "chrome"
                }
            };
            if(vmessConfig.tls === 'reality'){
                 outbound.tls.reality = {
                    enabled: true,
                    public_key: vmessConfig.pbk,
                    short_id: vmessConfig.sid || ""
                };
            }
        }

        // Transport settings for VMess: Crucial Change Here!
        const transportTypeNet = vmessConfig.net;
        if (transportTypeNet && transportTypeNet !== 'tcp') {
            outbound.transport = { type: transportTypeNet };
            if (transportTypeNet === 'ws') {
                outbound.transport.path = vmessConfig.path || "/";
                outbound.transport.headers = { Host: vmessConfig.host || vmessConfig.add };
            } else if (transportTypeNet === 'grpc') {
                outbound.transport.service_name = vmessConfig.path || vmessConfig.serviceName || "";
            } else if (transportTypeNet === 'h2') {
                outbound.transport.path = vmessConfig.path || "/";
                // For H2, 'host' in sing-box transport is an array of strings.
                // vmessConfig.host is usually a single string.
                outbound.transport.host = vmessConfig.host ? [vmessConfig.host] : [vmessConfig.add];
            }
            // QUIC, etc. can be added
        }
        // If transportTypeNet is 'tcp' or not specified, DO NOT add the transport object.
        
        return outbound;
    }

    function parseHysteria2Link(link) { // Hysteria2 always has its own transport characteristics, no "tcp" type issue
        const url = new URL(link.replace(/^hy2:\/\//, 'hysteria2://'));
        const params = new URLSearchParams(url.search);
        const remark = decodeURIComponent(url.hash.substring(1)) || `hy2_${url.hostname}_${url.port}`;
        const tag = sanitizeTag(remark);

        const outbound = {
            type: "hysteria2",
            tag: tag,
            server: url.hostname,
            server_port: parseInt(url.port),
            password: url.username || url.password || "",
            up_mbps: parseInt(params.get('upmbps') || params.get('up')) || 20, 
            down_mbps: parseInt(params.get('downmbps') || params.get('down')) || 100, 
            tls: {
                enabled: true,
                server_name: params.get('sni') || url.hostname,
                utls: { 
                    enabled: params.get('utls_enabled') === 'true',
                    fingerprint: params.get('fp') || "chrome" 
                },
                insecure: params.get('insecure') === '1' || params.get('allowInsecure') === '1', 
                alpn: params.get('alpn') ? params.get('alpn').split(',') : ["h3"],
            }
        };
        
        const obfsType = params.get('obfs');
        if (obfsType) {
            outbound.obfs = { 
                type: obfsType,
                password: params.get('obfs-password') || params.get('obfs_password') || ""
            };
        }
        return outbound;
    }

    // generateFullSingBoxConfig, copyConfig, downloadConfig, saveCurrentConfig,
    // saveConfigToLocalStorage, loadSavedConfigs functions remain the same as the previous complete script.
    // For brevity, I'm omitting them here, but they should be included from the previous full script.
    // Make sure to copy them from the previous response.

    function generateFullSingBoxConfig(outbounds) {
        const uniqueOutbounds = [];
        const seenTags = new Set();
        let tagCounter = 1;

        const standardOutbounds = [
            { type: "direct", tag: "direct" },
            { type: "block", tag: "block" },
            { type: "dns", tag: "dns-out"}
        ];

        for (const std_ob of standardOutbounds) {
            uniqueOutbounds.push(std_ob);
            seenTags.add(std_ob.tag);
        }

        const proxyOutbounds = [];
        for (const outbound of outbounds) {
            if (!outbound || !outbound.tag) continue;
            
            let newTag = outbound.tag;
            while (seenTags.has(newTag)) {
                newTag = `${outbound.tag}_${tagCounter++}`;
            }
            outbound.tag = newTag;
            seenTags.add(newTag);
            proxyOutbounds.push(outbound);
        }
        
        uniqueOutbounds.push(...proxyOutbounds);

        const proxyOutboundTags = proxyOutbounds.map(o => o.tag);
        let finalRouteOutboundTag = "direct";

        if (proxyOutboundTags.length > 1) {
            const autoSelectTag = "auto_select_proxies";
            if (!seenTags.has(autoSelectTag)) {
                uniqueOutbounds.push({
                    type: "urltest",
                    tag: autoSelectTag,
                    outbounds: proxyOutboundTags,
                    url: "http://www.gstatic.com/generate_204",
                    interval: "10m",
                    tolerance: 200
                });
                seenTags.add(autoSelectTag);
                finalRouteOutboundTag = autoSelectTag;
            } else { 
                finalRouteOutboundTag = proxyOutboundTags[0];
            }
        } else if (proxyOutboundTags.length === 1) {
            finalRouteOutboundTag = proxyOutboundTags[0];
        }
        
        const dnsQueryDetour = (finalRouteOutboundTag !== "direct" && seenTags.has(finalRouteOutboundTag)) ? finalRouteOutboundTag : "direct";

        return {
            log: {
                level: "info",
                timestamp: true
            },
            dns: {
                servers: [
                    { address: "tls://1.1.1.1", tag: "dns_cf_tls", detour: dnsQueryDetour },
                    { address: "https://dns.google/dns-query", tag: "dns_google_doh", detour: dnsQueryDetour },
                    { address: "1.0.0.1", tag: "dns_cf_plain_backup", detour: dnsQueryDetour},
                    { address: "223.5.5.5", tag: "dns_ali", detour: "direct" },
                    { address: "185.51.200.2", tag: "dns_shecan", detour: "direct" },
                    { address: "local", tag: "dns_system", detour: "direct" }
                ],
                rules: [
                    { geosite: ["category-ir"], server: "dns_ali" },
                    { domain_suffix: [".ir"], server: "dns_ali" },
                    { query_type: ["A", "AAAA"], server: "dns_cf_tls", rewrite_ttl: 300 },
                    { server: "dns_system" } 
                ],
                strategy: "ipv4_only",
                disable_cache: false,
            },
            inbounds: [
                {
                    type: "tun",
                    tag: "tun-in",
                    interface_name: "NotePadVPN-TUN",
                    inet4_address: "172.19.0.1/28",
                    auto_route: true,
                    strict_route: true,
                    stack: "mixed",
                    sniff: true,
                },
                {
                    type: "mixed",
                    tag: "mixed-proxy-in",
                    listen: "127.0.0.1",
                    listen_port: 2080,
                    sniff: true,
                }
            ],
            outbounds: uniqueOutbounds,
            route: {
                rules: [
                    { protocol: ["dns"], outbound: "dns-out" },
                    { domain: ["allatori.com", "analytics.example.com"], outbound: "block" },
                    { domain_keyword: ["ads", "tracker"], outbound: "block"},
                    { domain_suffix: [".ir", "arvancloud.ir", "arvancloud.com", "cdn.ir", "shaparak.ir", "digikala.com"], outbound: "direct" },
                    { geosite: ["category-ir"], outbound: "direct" },
                    { geoip: ["ir"], outbound: "direct" },
                    { ip_cidr: ["192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12"], outbound: "direct"},
                    { domain: ["localhost"], outbound: "direct"},
                ],
                final: finalRouteOutboundTag,
                auto_detect_interface: true,
                override_android_vpn: true,
            },
            experimental: {
                cache_file: {
                    enabled: true,
                },
            }
        };
    }

    function copyConfig() {
        if (outputConfigEl.value) {
            navigator.clipboard.writeText(outputConfigEl.value)
                .then(() => alert('Конфигурация успешно скопирована!'))
                .catch(err => {
                    console.error('Clipboard copy failed:', err);
                    prompt("Ошибка при автоматическом копировании. Пожалуйста, скопируйте с помощью Ctrl+C или Cmd+C.", outputConfigEl.value);
                });
        }
    }

    function downloadConfig() {
        if (outputConfigEl.value) {
            const blob = new Blob([outputConfigEl.value], { type: 'application/json;charset=utf-8' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            let fileName = (configNameEl.value.trim().replace(/[^\w\s._-]/g, '') || 'NotePadVPN_SingBox_Config');
            fileName = fileName.replace(/\s+/g, '_');
            a.href = url;
            a.download = fileName + '.json';
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
        }
    }
    
    function saveCurrentConfig() {
        if (!currentGeneratedConfig) {
            alert('Сохранять параметры конфигурации не нужно. Сначала сгенерируйте их.');
            return;
        }
        let name = configNameEl.value.trim();
        if (!name) {
            const timestamp = new Date().toLocaleDateString('fa-IR-u-nu-latn', { year: '2-digit', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' }).replace(/[\s/:]/g, '-').replace(',','_');
            name = prompt('Пожалуйста, введите название для этой конфигурации (только буквы, цифры и дефисы):', `Config_${timestamp}`);
        }
        
        if (name) {
            const sanitizedName = name.replace(/[^\w\s._-]/g, '').replace(/\s+/g, '_');
            if (!sanitizedName){
                alert("Введенное имя недействительно.");
                return;
            }
            saveConfigToLocalStorage(sanitizedName, currentGeneratedConfig);
            loadSavedConfigs();
            alert(`Конфигурация "${sanitizedName}" Сохранено успешно.`);
        }
    }

    function saveConfigToLocalStorage(name, config) {
        try {
            let savedConfigs = JSON.parse(localStorage.getItem('notepadVPN_SingBoxConfigs_v1.1') || '{}');
            savedConfigs[name] = config;
            localStorage.setItem('notepadVPN_SingBoxConfigs_v1.1', JSON.stringify(savedConfigs));
        } catch (e) {
            console.error("Error saving to localStorage:", e);
            alert('Ошибка сохранения конфигурации. Возможно, память браузера переполнена или предыдущие данные повреждены.');
        }
    }

    function loadSavedConfigs() {
        savedConfigsListEl.innerHTML = '';
        try {
            const savedConfigs = JSON.parse(localStorage.getItem('notepadVPN_SingBoxConfigs_v1.1') || '{}');
            if (Object.keys(savedConfigs).length === 0) {
                savedConfigsListEl.innerHTML = '<p class="empty-state">Настройки еще не сохранены.</p>';
                return;
            }

            Object.entries(savedConfigs).forEach(([name, configData]) => {
                const item = document.createElement('div');
                item.classList.add('saved-item');
                
                const nameSpan = document.createElement('span');
                nameSpan.textContent = name;
                nameSpan.title = `بارگذاری کانفیگ: ${name}`;

                const actionsDiv = document.createElement('div');
                actionsDiv.classList.add('actions');

                const loadButton = document.createElement('button');
                loadButton.classList.add('load', 'secondary-button');
                loadButton.textContent = 'Загрузка';
                loadButton.dataset.name = name;
                loadButton.addEventListener('click', (e) => {
                    const configName = e.target.dataset.name;
                    currentGeneratedConfig = savedConfigs[configName];
                    outputConfigEl.value = JSON.stringify(currentGeneratedConfig, null, 2);
                    configNameEl.value = configName;
                    
                    copyBtn.disabled = false;
                    downloadBtn.disabled = false;
                    saveConfigBtn.disabled = false; 
                    
                    const converterTabButton = document.querySelector('.tab-button[onclick*="\'converter\'"]');
                    if (converterTabButton) {
                        openTab({ currentTarget: converterTabButton }, 'converter', true);
                    }
                    
                    alert(`Конфигурация "${configName}" Загрузка прошла успешно, файл отобразился во вкладке "Конвертировать".`);
                    outputConfigEl.scrollTop = 0;
                });

                const deleteButton = document.createElement('button');
                deleteButton.classList.add('delete', 'secondary-button');
                deleteButton.textContent = 'Удалить';
                deleteButton.dataset.name = name;
                deleteButton.addEventListener('click', (e) => {
                    const configNameToDelete = e.target.dataset.name;
                    if (confirm(`Вы уверены, что хотите удалить сохраненную конфигурацию с этим именем? "${configNameToDelete}" Вы уверены? Это действие необратимо.`)) {
                        delete savedConfigs[configNameToDelete];
                        localStorage.setItem('notepadVPN_SingBoxConfigs_v1.1', JSON.stringify(savedConfigs));
                        loadSavedConfigs();
                        alert(`Конфигурация "${configNameToDelete}" Удалено.`);
                    }
                });
                
                actionsDiv.appendChild(loadButton);
                actionsDiv.appendChild(deleteButton);
                item.appendChild(nameSpan);
                item.appendChild(actionsDiv);
                savedConfigsListEl.appendChild(item);
            });

        } catch (e) {
            console.error("Error loading configs from localStorage:", e);
            savedConfigsListEl.innerHTML = '<p class="empty-state">Ошибка загрузки сохраненных конфигураций. Ранее сохраненные данные могут быть повреждены.</p>';
        }
    }
});

function openTab(event, tabName, forceOpen = false) {
    let i, tabcontent, tabbuttons;
    
    tabcontent = document.getElementsByClassName("tab-content");
    for (i = 0; i < tabcontent.length; i++) {
        tabcontent[i].classList.remove("active");
    }
    
    tabbuttons = document.getElementsByClassName("tab-button");
    for (i = 0; i < tabbuttons.length; i++) {
        tabbuttons[i].classList.remove("active");
    }
    
    const activeTabContent = document.getElementById(tabName);
    if (activeTabContent) {
        activeTabContent.classList.add("active");
    }

    if (event && event.currentTarget && !forceOpen) { 
      event.currentTarget.classList.add("active");
    } else { 
        for (i = 0; i < tabbuttons.length; i++) {
            if (tabbuttons[i].getAttribute('onclick') && tabbuttons[i].getAttribute('onclick').includes(`'${tabName}'`)) {
                tabbuttons[i].classList.add("active");
                break;
            }
        }
    }
}
