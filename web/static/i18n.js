const translations = {
    ru: {
        dashboard: 'Dashboard',
        scans: 'Сканы',
        risks: 'Риски',
        newScan: 'Новый скан',
        scansInProgress: 'сканов в процессе',
        scan: 'скан',
        inProgress: 'в процессе',
        showingLatest: 'Показаны результаты последнего скана',
        noScansYet: 'Сканов пока нет',
        dashboardNote: 'Dashboard показывает статистику последнего завершённого скана. Кликните на скан для детальной информации.',
        critical: 'Critical',
        high: 'High',
        medium: 'Medium',
        low: 'Low',
        info: 'Info',
        recentScans: 'Последние сканы',
        seeAllScans: 'Все сканы →',
        recentRisks: 'Недавние риски',
        seeAllRisks: 'Все риски →',
        noScansClickNew: 'Сканов пока нет. Нажмите "Новый скан" для начала.',
        noScansYetClickNew: 'Сканов пока нет. Нажмите "Новый скан" для начала.',
        noRisksYet: 'Риски пока не обнаружены.',
        allScans: 'Все сканы',
        allRisks: 'Все риски',
        all: 'Все',
        filter: 'Фильтр',
        noRisksMatch: 'Нет рисков соответствующих фильтру.',
        newScanTitle: 'Новый скан',
        targetUrl: 'Целевой URL',
        targetUrlPlaceholder: 'https://target/',
        profile: 'Профиль',
        profileFull: 'Full (все модули)',
        profileLight: 'Light (headers, paths, xss)',
        profileHardening: 'Hardening (security headers)',
        profileApi: 'API (jsmap, apis, cors, reflect)',
        profileCustom: 'Пользовательские модули',
        customModules: 'Пользовательские модули (через запятую)',
        customModulesPlaceholder: 'headers,paths,xss',
        maxRps: 'Макс. RPS',
        cancel: 'Отмена',
        startScan: 'Запустить скан',
        scanDetails: 'Детали скана',
        scanInformation: 'Информация о скане',
        status: 'Статус',
        started: 'Начат',
        completed: 'Завершён',
        totalFindings: 'Всего находок',
        findings: 'Находки',
        scanRunning: 'Скан выполняется...',
        noFindings: 'Находок не обнаружено.',
        running: 'Выполняется...',
        completedStatus: 'Завершён',
        error: 'Ошибка',
        findingsDetected: 'находок обнаружено',
        findingsDetectedLatest: 'находок обнаружено в последнем скане',
        clickToView: 'Кликните для просмотра всех находок этого скана',
        module: 'Модуль',
        target: 'Цель',
        required: '*',
        evasionLabel: 'Evasion (доп. варианты)',
        modulesUsed: 'Использованные модули'
    },
    en: {
        dashboard: 'Dashboard',
        scans: 'Scans',
        risks: 'Risks',
        newScan: 'New Scan',
        scansInProgress: 'scans in progress',
        scan: 'scan',
        inProgress: 'in progress',
        showingLatest: 'Showing latest scan results',
        noScansYet: 'No scans yet',
        dashboardNote: 'Dashboard shows statistics from the latest completed scan. Click on a scan for detailed information.',
        critical: 'Critical',
        high: 'High',
        medium: 'Medium',
        low: 'Low',
        info: 'Info',
        recentScans: 'Recent Scans',
        seeAllScans: 'See all scans →',
        recentRisks: 'Recent Risks',
        seeAllRisks: 'See all risks →',
        noScansClickNew: 'No scans yet. Click "New Scan" to start.',
        noScansYetClickNew: 'No scans yet. Click "New Scan" to start.',
        noRisksYet: 'No risks detected yet.',
        allScans: 'All Scans',
        allRisks: 'All Risks',
        all: 'All',
        filter: 'Filter',
        noRisksMatch: 'No risks match the filter.',
        newScanTitle: 'New Scan',
        targetUrl: 'Target URL',
        targetUrlPlaceholder: 'https://target/',
        profile: 'Profile',
        profileFull: 'Full (all modules)',
        profileLight: 'Light (headers, paths, xss)',
        profileHardening: 'Hardening (security headers)',
        profileApi: 'API (jsmap, apis, cors, reflect)',
        profileCustom: 'Custom modules',
        customModules: 'Custom Modules (comma separated)',
        customModulesPlaceholder: 'headers,paths,xss',
        maxRps: 'Max RPS',
        cancel: 'Cancel',
        startScan: 'Start Scan',
        scanDetails: 'Scan Details',
        scanInformation: 'Scan Information',
        status: 'Status',
        started: 'Started',
        completed: 'Completed',
        totalFindings: 'Total Findings',
        findings: 'Findings',
        scanRunning: 'Scan is still running...',
        noFindings: 'No findings detected.',
        running: 'Running...',
        completedStatus: 'Completed',
        error: 'Error',
        findingsDetected: 'findings detected',
        findingsDetectedLatest: 'findings detected in latest scan',
        clickToView: 'Click to view all findings from this scan',
        module: 'Module',
        target: 'Target',
        required: '*',
        evasionLabel: 'Evasion (extra variants)',
        modulesUsed: 'Modules Used'
    }
};

let currentLang = localStorage.getItem('vulnscan_lang') || 'ru';

function t(key) {
    return translations[currentLang][key] || key;
}

function setLanguage(lang) {
    currentLang = lang;
    localStorage.setItem('vulnscan_lang', lang);
    updateUILanguage();
    
    // Update active button
    document.querySelectorAll('.lang-btn').forEach(btn => {
        btn.classList.toggle('active', btn.dataset.lang === lang);
    });
}

function updateUILanguage() {
    // Update all elements with data-i18n attribute
    document.querySelectorAll('[data-i18n]').forEach(el => {
        const key = el.getAttribute('data-i18n');
        if (el.tagName === 'INPUT' && el.placeholder !== undefined) {
            el.placeholder = t(key);
        } else {
            el.textContent = t(key);
        }
    });
    
    // Update header title based on current view
    const headerTitle = document.getElementById('headerTitle');
    if (headerTitle) {
        const dashboardView = document.getElementById('dashboardView');
        const scansView = document.getElementById('scansView');
        const risksView = document.getElementById('risksView');
        
        if (scansView && scansView.style.display !== 'none') {
            headerTitle.textContent = t('scans');
        } else if (risksView && risksView.style.display !== 'none') {
            headerTitle.textContent = t('risks');
        } else {
            headerTitle.textContent = t('dashboard');
        }
    }
    
    // Reload dynamic content
    if (typeof loadStats === 'function') loadStats();
    if (typeof loadScans === 'function') loadScans();
}

// Initialize on load
document.addEventListener('DOMContentLoaded', () => {
    // Set active language button
    document.querySelectorAll('.lang-btn').forEach(btn => {
        btn.classList.toggle('active', btn.dataset.lang === currentLang);
    });
    
    // Update UI after a short delay to ensure DOM is ready
    setTimeout(() => {
        updateUILanguage();
    }, 50);
});
