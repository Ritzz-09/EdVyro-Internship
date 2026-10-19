// Task 03: SOC Investigation Console Client Logic

function switchTab(tabId) {
    // Hide all contents
    document.querySelectorAll('.tab-content').forEach(el => {
        el.classList.remove('active');
    });
    // Remove active from all buttons
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.classList.remove('active');
    });

    // Activate selected
    const target = document.getElementById('tab-' + tabId);
    if (target) {
        target.classList.add('active');
    }
    // Highlight button
    event.currentTarget.classList.add('active');
}

function filterLogs() {
    const input = document.getElementById('logSearch');
    const filter = input.value.toLowerCase();
    const table = document.getElementById('logsTable');
    const tr = table.getElementsByTagName('tr');

    for (let i = 1; i < tr.length; i++) {
        const text = tr[i].textContent || tr[i].innerText;
        if (text.toLowerCase().indexOf(filter) > -1) {
            tr[i].style.display = '';
        } else {
            tr[i].style.display = 'none';
        }
    }
}

async function executeContainment(action, target) {
    try {
        const response = await fetch(`/api/containment/${action}`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ target: target })
        });

        const data = await response.json();
        if (data.success) {
            const list = document.getElementById('containmentLogList');
            // Remove empty state if present
            const emptyState = list.querySelector('.empty-state');
            if (emptyState) {
                emptyState.remove();
            }

            const now = new Date().toISOString().substring(11, 19) + ' UTC';
            const li = document.createElement('li');
            li.innerHTML = `<strong>[${now}]</strong> ${data.message}`;
            list.insertBefore(li, list.firstChild);
        } else {
            alert('Containment action error: ' + (data.error || 'Failed'));
        }
    } catch (err) {
        console.error(err);
        alert('Network error executing containment action.');
    }
}
