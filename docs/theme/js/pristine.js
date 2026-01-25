/**
 * Pristine Theme - JavaScript
 * Modern, minimal MkDocs theme
 */

(function() {
    'use strict';

    // ============================================
    // Theme Toggle
    // ============================================

    const ThemeToggle = {
        storageKey: 'pristine-theme',

        init() {
            const toggle = document.getElementById('theme-toggle');
            if (!toggle) return;

            // Set initial theme
            const savedTheme = localStorage.getItem(this.storageKey);
            const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
            const initialTheme = savedTheme || (prefersDark ? 'dark' : 'light');

            this.setTheme(initialTheme);

            // Handle toggle click
            toggle.addEventListener('click', () => {
                const currentTheme = document.documentElement.getAttribute('data-theme');
                const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
                this.setTheme(newTheme);
                localStorage.setItem(this.storageKey, newTheme);
            });

            // Listen for system preference changes
            window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', (e) => {
                if (!localStorage.getItem(this.storageKey)) {
                    this.setTheme(e.matches ? 'dark' : 'light');
                }
            });
        },

        setTheme(theme) {
            document.documentElement.setAttribute('data-theme', theme);
        }
    };

    // ============================================
    // Search Modal with MkDocs Integration
    // ============================================

    const SearchModal = {
        worker: null,
        index: null,
        selectedIndex: -1,

        init() {
            const trigger = document.getElementById('search-trigger');
            const modal = document.getElementById('search-modal');
            const input = document.getElementById('search-input');
            const results = document.getElementById('search-results');
            const backdrop = modal?.querySelector('.search-modal-backdrop');

            if (!trigger || !modal) return;

            // Store references
            this.modal = modal;
            this.input = input;
            this.results = results;

            // Initialize search worker
            this.initSearchWorker();

            // Open modal
            const openModal = () => {
                modal.classList.add('active');
                document.body.style.overflow = 'hidden';
                this.selectedIndex = -1;
                setTimeout(() => input?.focus(), 100);
            };

            // Close modal
            this.closeModal = () => {
                modal.classList.remove('active');
                document.body.style.overflow = '';
                if (input) input.value = '';
                if (results) results.innerHTML = '';
                this.selectedIndex = -1;
            };

            trigger.addEventListener('click', openModal);
            backdrop?.addEventListener('click', this.closeModal);

            // Click on result - close modal
            results.addEventListener('click', (e) => {
                const link = e.target.closest('.search-result-item');
                if (link) {
                    this.closeModal();
                }
            });

            // Keyboard shortcuts
            document.addEventListener('keydown', (e) => {
                // Cmd/Ctrl + K to open
                if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
                    e.preventDefault();
                    if (modal.classList.contains('active')) {
                        this.closeModal();
                    } else {
                        openModal();
                    }
                }

                // Only handle these when modal is active
                if (!modal.classList.contains('active')) return;

                // Escape to close
                if (e.key === 'Escape') {
                    this.closeModal();
                    return;
                }

                // Arrow navigation
                const items = results.querySelectorAll('.search-result-item');
                if (items.length === 0) return;

                if (e.key === 'ArrowDown') {
                    e.preventDefault();
                    this.selectedIndex = Math.min(this.selectedIndex + 1, items.length - 1);
                    this.updateSelection(items);
                } else if (e.key === 'ArrowUp') {
                    e.preventDefault();
                    this.selectedIndex = Math.max(this.selectedIndex - 1, 0);
                    this.updateSelection(items);
                } else if (e.key === 'Enter' && this.selectedIndex >= 0) {
                    e.preventDefault();
                    const selectedItem = items[this.selectedIndex];
                    if (selectedItem) {
                        this.closeModal();
                        window.location.href = selectedItem.href;
                    }
                }
            });

            // Search input handler
            if (input && results) {
                let debounceTimer;

                input.addEventListener('input', (e) => {
                    clearTimeout(debounceTimer);
                    const query = e.target.value.trim();
                    this.selectedIndex = -1;

                    if (query.length < 2) {
                        results.innerHTML = '';
                        return;
                    }

                    debounceTimer = setTimeout(() => {
                        this.performSearch(query, results);
                    }, 150);
                });
            }
        },

        updateSelection(items) {
            items.forEach((item, index) => {
                if (index === this.selectedIndex) {
                    item.classList.add('selected');
                    item.scrollIntoView({ block: 'nearest' });
                } else {
                    item.classList.remove('selected');
                }
            });
        },

        initSearchWorker() {
            // Get base_url from MkDocs
            const baseUrl = typeof base_url !== 'undefined' ? base_url : '.';

            // Load search index
            fetch(`${baseUrl}/search/search_index.json`)
                .then(response => response.json())
                .then(data => {
                    this.index = data;
                })
                .catch(err => console.error('Failed to load search index:', err));
        },

        performSearch(query, resultsContainer) {
            if (!this.index || !this.index.docs) {
                resultsContainer.innerHTML = '<div class="search-empty"><p>Search index not loaded</p></div>';
                return;
            }

            const queryLower = query.toLowerCase();
            const results = [];

            // Simple search through docs
            for (const doc of this.index.docs) {
                const titleMatch = doc.title && doc.title.toLowerCase().includes(queryLower);
                const textMatch = doc.text && doc.text.toLowerCase().includes(queryLower);

                if (titleMatch || textMatch) {
                    let summary = '';
                    if (doc.text) {
                        const idx = doc.text.toLowerCase().indexOf(queryLower);
                        if (idx !== -1) {
                            const start = Math.max(0, idx - 50);
                            const end = Math.min(doc.text.length, idx + query.length + 100);
                            summary = (start > 0 ? '...' : '') +
                                      doc.text.substring(start, end) +
                                      (end < doc.text.length ? '...' : '');
                        } else {
                            summary = doc.text.substring(0, 150) + (doc.text.length > 150 ? '...' : '');
                        }
                    }

                    results.push({
                        title: doc.title || 'Untitled',
                        location: doc.location,
                        summary: summary,
                        score: titleMatch ? 2 : 1
                    });
                }
            }

            // Sort by score (title matches first)
            results.sort((a, b) => b.score - a.score);

            this.renderResults(results.slice(0, 10), resultsContainer, query);
        },

        renderResults(results, container, query) {
            if (!results || results.length === 0) {
                container.innerHTML = `
                    <div class="search-empty">
                        <p>No results found for "${this.escapeHtml(query)}"</p>
                    </div>
                `;
                return;
            }

            const baseUrl = typeof base_url !== 'undefined' ? base_url : '.';
            const html = results.map(result => `
                <a href="${baseUrl}/${result.location}" class="search-result-item">
                    <div class="search-result-title">${this.escapeHtml(result.title)}</div>
                    <div class="search-result-text">${this.highlightQuery(result.summary, query)}</div>
                </a>
            `).join('');

            container.innerHTML = html;
        },

        escapeHtml(text) {
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        },

        highlightQuery(text, query) {
            if (!text || !query) return this.escapeHtml(text);
            const escaped = this.escapeHtml(text);
            const regex = new RegExp(`(${query.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')})`, 'gi');
            return escaped.replace(regex, '<mark>$1</mark>');
        }
    };

    // ============================================
    // Mobile Navigation
    // ============================================

    const MobileNav = {
        init() {
            const toggle = document.getElementById('mobile-toggle');
            const nav = document.getElementById('mobile-nav');

            if (!toggle || !nav) return;

            toggle.addEventListener('click', () => {
                const isActive = nav.classList.toggle('active');
                toggle.classList.toggle('active', isActive);
                document.body.style.overflow = isActive ? 'hidden' : '';

                // Animate hamburger
                const spans = toggle.querySelectorAll('span');
                if (isActive) {
                    spans[0].style.transform = 'rotate(45deg) translate(5px, 5px)';
                    spans[1].style.opacity = '0';
                    spans[2].style.transform = 'rotate(-45deg) translate(5px, -5px)';
                } else {
                    spans[0].style.transform = '';
                    spans[1].style.opacity = '';
                    spans[2].style.transform = '';
                }
            });

            // Close on navigation
            nav.querySelectorAll('a').forEach(link => {
                link.addEventListener('click', () => {
                    nav.classList.remove('active');
                    toggle.classList.remove('active');
                    document.body.style.overflow = '';
                });
            });
        }
    };

    // ============================================
    // Table of Contents Highlighting
    // ============================================

    const TOCHighlight = {
        init() {
            const toc = document.querySelector('.toc-nav');
            if (!toc) return;

            const links = toc.querySelectorAll('.toc-link');
            const headings = Array.from(links).map(link => {
                const id = link.getAttribute('href')?.substring(1);
                return id ? document.getElementById(id) : null;
            }).filter(Boolean);

            if (headings.length === 0) return;

            const observer = new IntersectionObserver(
                (entries) => {
                    entries.forEach(entry => {
                        if (entry.isIntersecting) {
                            const id = entry.target.id;
                            this.setActive(links, id);
                        }
                    });
                },
                {
                    rootMargin: '-20% 0px -80% 0px',
                    threshold: 0
                }
            );

            headings.forEach(heading => observer.observe(heading));
        },

        setActive(links, id) {
            links.forEach(link => {
                const linkId = link.getAttribute('href')?.substring(1);
                link.classList.toggle('active', linkId === id);
            });
        }
    };

    // ============================================
    // Code Block Enhancements
    // ============================================

    const CodeBlocks = {
        init() {
            const codeBlocks = document.querySelectorAll('pre code');

            codeBlocks.forEach(code => {
                const pre = code.parentElement;
                if (!pre) return;

                // Add copy button
                const copyBtn = document.createElement('button');
                copyBtn.className = 'copy-button';
                copyBtn.innerHTML = `
                    <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2">
                        <rect x="9" y="9" width="13" height="13" rx="2" ry="2"/>
                        <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>
                    </svg>
                `;
                copyBtn.setAttribute('aria-label', 'Copy code');

                copyBtn.addEventListener('click', async () => {
                    try {
                        await navigator.clipboard.writeText(code.textContent || '');
                        copyBtn.classList.add('copied');
                        copyBtn.innerHTML = `
                            <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2">
                                <polyline points="20 6 9 17 4 12"/>
                            </svg>
                        `;

                        setTimeout(() => {
                            copyBtn.classList.remove('copied');
                            copyBtn.innerHTML = `
                                <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2">
                                    <rect x="9" y="9" width="13" height="13" rx="2" ry="2"/>
                                    <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>
                                </svg>
                            `;
                        }, 2000);
                    } catch (err) {
                        console.error('Failed to copy:', err);
                    }
                });

                pre.style.position = 'relative';
                pre.appendChild(copyBtn);

                // Add language label if class contains language-
                const langClass = Array.from(code.classList).find(c => c.startsWith('language-'));
                if (langClass) {
                    const lang = langClass.replace('language-', '');
                    pre.setAttribute('data-lang', lang);
                }
            });
        }
    };

    // ============================================
    // Smooth Anchor Scrolling
    // ============================================

    const SmoothScroll = {
        init() {
            document.querySelectorAll('a[href^="#"]').forEach(anchor => {
                anchor.addEventListener('click', (e) => {
                    const targetId = anchor.getAttribute('href')?.substring(1);
                    if (!targetId) return;

                    const target = document.getElementById(targetId);
                    if (!target) return;

                    e.preventDefault();

                    const headerHeight = document.querySelector('.site-header')?.offsetHeight || 0;
                    const targetPosition = target.getBoundingClientRect().top + window.scrollY - headerHeight - 20;

                    window.scrollTo({
                        top: targetPosition,
                        behavior: 'smooth'
                    });

                    // Update URL without jumping
                    history.pushState(null, '', `#${targetId}`);
                });
            });
        }
    };

    // ============================================
    // External Links
    // ============================================

    const ExternalLinks = {
        init() {
            const currentHost = window.location.host;

            document.querySelectorAll('.article a[href^="http"]').forEach(link => {
                const href = link.getAttribute('href');
                if (href && !href.includes(currentHost)) {
                    link.setAttribute('target', '_blank');
                    link.setAttribute('rel', 'noopener noreferrer');
                }
            });
        }
    };

    // ============================================
    // Badges Detection
    // ============================================

    const Badges = {
        init() {
            // Find paragraphs that contain only image links (badges)
            document.querySelectorAll('.article p').forEach(p => {
                const children = Array.from(p.childNodes);
                const hasOnlyBadges = children.every(node => {
                    // Allow whitespace text nodes
                    if (node.nodeType === Node.TEXT_NODE && !node.textContent.trim()) {
                        return true;
                    }
                    // Allow anchor tags with images
                    if (node.nodeType === Node.ELEMENT_NODE && node.tagName === 'A') {
                        return node.querySelector('img') !== null;
                    }
                    return false;
                });

                if (hasOnlyBadges && p.querySelector('a img')) {
                    p.classList.add('badges');
                }
            });
        }
    };

    // ============================================
    // Initialize Everything
    // ============================================

    document.addEventListener('DOMContentLoaded', () => {
        ThemeToggle.init();
        SearchModal.init();
        MobileNav.init();
        TOCHighlight.init();
        CodeBlocks.init();
        SmoothScroll.init();
        ExternalLinks.init();
        Badges.init();
    });

})();
