// Główna funkcja inicjalizacyjna
window.addEventListener('pywebviewready', function() {
    // Rozpoczęcie monitorowania systemu
    window.pywebview.api.start_monitoring()
        .then(() => {
            console.log('Monitoring started');
            // Rozpoczęcie aktualizacji statystyk
            updateStats();
        })
        .catch(error => {
            console.error('Error starting monitoring:', error);
        });

    // Przycisk optymalizacji
    document.getElementById('optimize-btn').addEventListener('click', optimizeSystem);
});

// Funkcja aktualizująca statystyki co sekundę
function updateStats() {
    setInterval(() => {
        window.pywebview.api.get_current_stats()
            .then(stats => {
                // Aktualizacja CPU
                const cpuProgress = document.getElementById('cpu-progress');
                const cpuPercent = document.getElementById('cpu-percent');
                cpuProgress.style.width = `${stats.cpu_percent}%`;
                cpuPercent.textContent = `${stats.cpu_percent.toFixed(1)}%`;

                // Zmiana koloru wskaźnika CPU w zależności od obciążenia
                if (stats.cpu_percent > 80) {
                    cpuProgress.style.backgroundColor = '#ff4d4d'; // Czerwony dla wysokiego użycia
                } else if (stats.cpu_percent > 50) {
                    cpuProgress.style.backgroundColor = '#ffa64d'; // Pomarańczowy dla średniego użycia
                } else {
                    cpuProgress.style.backgroundColor = '#24b47e'; // Zielony dla niskiego użycia
                }

                // Aktualizacja RAM
                const memoryProgress = document.getElementById('memory-progress');
                const memoryPercent = document.getElementById('memory-percent');
                memoryProgress.style.width = `${stats.memory_percent}%`;
                memoryPercent.textContent = `${stats.memory_percent.toFixed(1)}%`;

                // Zmiana koloru wskaźnika RAM
                if (stats.memory_percent > 80) {
                    memoryProgress.style.backgroundColor = '#ff4d4d';
                } else if (stats.memory_percent > 50) {
                    memoryProgress.style.backgroundColor = '#ffa64d';
                } else {
                    memoryProgress.style.backgroundColor = '#24b47e';
                }

                // Aktualizacja Dysku
                const diskProgress = document.getElementById('disk-progress');
                const diskPercent = document.getElementById('disk-percent');
                diskProgress.style.width = `${stats.disk_percent}%`;
                diskPercent.textContent = `${stats.disk_percent.toFixed(1)}%`;

                // Zmiana koloru wskaźnika Dysku
                if (stats.disk_percent > 80) {
                    diskProgress.style.backgroundColor = '#ff4d4d';
                } else if (stats.disk_percent > 50) {
                    diskProgress.style.backgroundColor = '#ffa64d';
                } else {
                    diskProgress.style.backgroundColor = '#24b47e';
                }

                // Aktualizacja informacji o systemie
                document.getElementById('system-name').textContent = `System: ${stats.system_name}`;
                document.getElementById('cpu-name').textContent = `Procesor: ${stats.cpu_name}`;
            })
            .catch(error => {
                console.error('Error fetching stats:', error);
            });
    }, 1000);
}

// Funkcja do optymalizacji systemu
function optimizeSystem() {
    const button = document.getElementById('optimize-btn');
    button.disabled = true;
    button.textContent = 'Optymalizacja w toku...';

    window.pywebview.api.optimize_system()
        .then(result => {
            // Wyświetl wyniki optymalizacji
            document.getElementById('results-message').textContent = result.message;

            // Wyczyść i zaktualizuj listę zoptymalizowanych obszarów
            const optimizedAreasList = document.getElementById('optimized-areas');
            optimizedAreasList.innerHTML = '';

            result.optimized_areas.forEach(area => {
                const li = document.createElement('li');
                li.textContent = area;
                optimizedAreasList.appendChild(li);
            });

            // Pokaż kontener z wynikami
            document.getElementById('optimization-results').classList.remove('hidden');

            // Przywróć przycisk
            button.disabled = false;
            button.textContent = 'Optymalizuj system';
        })
        .catch(error => {
            console.error('Optimization error:', error);
            button.disabled = false;
            button.textContent = 'Optymalizuj system';
        });
}

// Funkcja wywoływana przy zamknięciu aplikacji
window.addEventListener('unload', () => {
    window.pywebview.api.stop_monitoring();
});