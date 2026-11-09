<script lang="ts">
	import { resolve } from '$app/paths';
	import { onMount } from 'svelte';
	import {
		deleteContainer,
		getProvisioningDrift,
		getNetworkState,
		getSystemHealth,
		listContainers,
		type ActiveConnection,
		type ContainerRecord,
		type ProvisioningDrift,
		type ServiceHealth,
		type SystemHealth,
		type NetworkState
	} from '#lib/containers.js';

	const pageSize = 50;

	let activeTab = $state<'containers' | 'authorized' | 'connections'>('containers');
	let containers = $state<ContainerRecord[]>([]);
	let networkState = $state<NetworkState | null>(null);
	let total = $state(0);
	let offset = $state(0);
	let search = $state('');
	let loading = $state(true);
	let deleting = $state(false);
	let networkLoading = $state(true);
	let error = $state('');
	let networkError = $state('');
	let notice = $state('');
	let pendingDelete = $state<ContainerRecord | null>(null);
	let searchInput = $state<HTMLInputElement>();
	let searchTimer: ReturnType<typeof setTimeout> | undefined;
	let requestVersion = 0;
	let networkRequestInFlight = false;
	let healthRequestInFlight = false;
	let driftRequestInFlight = false;
	let lastNetworkUpdate = $state('');
	let health = $state<SystemHealth | null>(null);
	let healthLoading = $state(true);
	let healthError = $state('');
	let lastHealthUpdate = $state('');
	let drift = $state<ProvisioningDrift | null>(null);
	let driftLoading = $state(true);
	let driftError = $state('');

	const page = $derived(Math.floor(offset / pageSize) + 1);
	const pageCount = $derived(Math.max(1, Math.ceil(total / pageSize)));
	const rangeStart = $derived(total === 0 ? 0 : offset + 1);
	const rangeEnd = $derived(Math.min(offset + containers.length, total));
	const overallHealth = $derived(
		healthError || (!health && !healthLoading)
			? 'error'
			: !health || healthLoading
				? 'loading'
				: health.services.some((service) => service.status === 'error')
					? 'error'
					: health.services.some((service) => service.status === 'mock')
						? 'warning'
						: 'ok'
	);
	const driftCount = $derived(
		(drift?.kernel_drifted_items.length ?? 0) + (drift?.db_pending_items.length ?? 0)
	);

	async function loadContainers() {
		const version = ++requestVersion;
		loading = true;
		error = '';

		try {
			const result = await listContainers({ search, limit: pageSize, offset });
			if (version !== requestVersion) return;
			containers = result.items;
			total = result.total;
		} catch (cause) {
			if (version === requestVersion) {
				error = cause instanceof Error ? cause.message : 'Errore durante il caricamento.';
			}
		} finally {
			if (version === requestVersion) loading = false;
		}
	}

	async function loadNetworkState() {
		if (networkRequestInFlight) return;
		networkRequestInFlight = true;
		networkLoading = true;
		networkError = '';
		try {
			networkState = await getNetworkState();
			lastNetworkUpdate = networkState.observed_at;
		} catch (cause) {
			networkError = cause instanceof Error ? cause.message : 'Stato rete non disponibile.';
		} finally {
			networkRequestInFlight = false;
			networkLoading = false;
		}
	}

	async function loadSystemHealth() {
		if (healthRequestInFlight) return;
		healthRequestInFlight = true;
		healthLoading = true;
		healthError = '';
		try {
			health = await getSystemHealth();
			lastHealthUpdate = health.checked_at;
		} catch (cause) {
			healthError = cause instanceof Error ? cause.message : 'Stato dei servizi non disponibile.';
		} finally {
			healthRequestInFlight = false;
			healthLoading = false;
		}
	}

	async function loadProvisioningDrift() {
		if (driftRequestInFlight) return;
		driftRequestInFlight = true;
		driftLoading = true;
		driftError = '';
		try {
			drift = await getProvisioningDrift();
		} catch (cause) {
			driftError = cause instanceof Error ? cause.message : 'Verifica drift non disponibile.';
		} finally {
			driftRequestInFlight = false;
			driftLoading = false;
		}
	}

	function refreshDiagnostics() {
		void Promise.all([loadSystemHealth(), loadProvisioningDrift()]);
	}

	function refreshAll() {
		void Promise.all([
			loadContainers(),
			loadNetworkState(),
			loadSystemHealth(),
			loadProvisioningDrift()
		]);
	}

	function onSearchInput(event: Event) {
		search = (event.currentTarget as HTMLInputElement).value;
		offset = 0;
		if (searchTimer) clearTimeout(searchTimer);
		searchTimer = setTimeout(() => void loadContainers(), 250);
	}

	function openDeleteDialog(container: ContainerRecord) {
		pendingDelete = container;
		notice = '';
	}

	async function confirmDelete() {
		if (!pendingDelete || deleting) return;

		const target = pendingDelete;
		deleting = true;
		error = '';
		try {
			await deleteContainer(target.vmid);
			notice = `Container ${target.vmid} rimosso dal registro.`;
			pendingDelete = null;
			if (containers.length === 1 && offset > 0) offset = Math.max(0, offset - pageSize);
			await Promise.all([loadContainers(), loadNetworkState()]);
		} catch (cause) {
			error = cause instanceof Error ? cause.message : 'Impossibile eliminare il container.';
		} finally {
			deleting = false;
		}
	}

	function formatDate(value: string | null) {
		if (!value) return '—';
		const date = new Date(value);
		return Number.isNaN(date.getTime())
			? value
			: new Intl.DateTimeFormat('it-IT', { dateStyle: 'medium' }).format(date);
	}

	function stateLabel(container: ContainerRecord) {
		if (!container.is_enabled) return 'Disabilitato';
		if (container.actual_state === 'SYNCED') return 'Sincronizzato';
		if (container.actual_state === 'ERROR') return 'Errore';
		if (container.actual_state === 'DRIFTED') return 'Disallineato';
		return 'In attesa';
	}

	function stateClass(container: ContainerRecord) {
		if (!container.is_enabled || container.actual_state === 'ERROR') return 'state-muted';
		if (container.actual_state === 'SYNCED') return 'state-good';
		if (container.actual_state === 'DRIFTED') return 'state-warning';
		return 'state-pending';
	}

	function serviceStateLabel(state: ServiceHealth['status']) {
		if (state === 'ok') return 'Operativo';
		if (state === 'mock') return 'Mock';
		return 'Non disponibile';
	}

	function connectionPeer(connection: ActiveConnection, side: 'source' | 'destination') {
		const ip = side === 'source' ? connection.source_ip : connection.destination_ip;
		const port = side === 'source' ? connection.source_port : connection.destination_port;
		const container =
			side === 'source' ? connection.source_container : connection.destination_container;
		const label = container
			? `${container.hostname_hint || `CT-${container.vmid}`} · @${container.username}`
			: ip;
		return port === undefined ? label : `${label}:${port}`;
	}

	onMount(() => {
		const onShortcut = (event: KeyboardEvent) => {
			if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === 'k') {
				event.preventDefault();
				searchInput?.focus();
			}
		};
		window.addEventListener('keydown', onShortcut);
		const refreshNetworkWhenVisible = () => {
			if (document.visibilityState === 'visible') {
				void loadNetworkState();
				refreshDiagnostics();
			}
		};
		refreshAll();
		const networkRefresh = window.setInterval(refreshNetworkWhenVisible, 15000);
		const diagnosticsRefresh = window.setInterval(refreshDiagnostics, 30000);
		document.addEventListener('visibilitychange', refreshNetworkWhenVisible);
		return () => {
			window.removeEventListener('keydown', onShortcut);
			window.clearInterval(networkRefresh);
			window.clearInterval(diagnosticsRefresh);
			document.removeEventListener('visibilitychange', refreshNetworkWhenVisible);
			if (searchTimer) clearTimeout(searchTimer);
		};
	});
</script>

<svelte:head>
	<title>Container · LabCtl Admin</title>
	<meta name="description" content="Gestione amministrativa dei container registrati in LabCtl." />
</svelte:head>

<div class="app-shell">
	<aside class="sidebar">
		<a class="brand" href={resolve('/')} aria-label="LabCtl Admin, pagina iniziale">
			<span class="brand-mark">L</span>
			<span class="brand-copy">
				<strong>labctl</strong>
				<small>CONTROL PLANE</small>
			</span>
		</a>

		<div class="nav-caption">GESTIONE</div>
		<nav aria-label="Navigazione principale">
			<a class="nav-item active" href="#containers" aria-current="page">
				<svg viewBox="0 0 24 24" aria-hidden="true">
					<rect x="3.5" y="4" width="17" height="6.5" rx="1.5"></rect>
					<rect x="3.5" y="13.5" width="17" height="6.5" rx="1.5"></rect>
					<path d="M7.5 7.25h.01M7.5 16.75h.01M11 7.25h5M11 16.75h5"></path>
				</svg>
				<span>Container</span>
				<span class="nav-count">{total}</span>
			</a>
		</nav>

		<div class="sidebar-bottom">
			<div class="secure-mark">
				<svg viewBox="0 0 24 24" aria-hidden="true">
					<path d="M12 3.5 19 6v5.5c0 4.3-2.8 7.3-7 9-4.2-1.7-7-4.7-7-9V6l7-2.5Z"></path>
					<path d="m9 12 2 2 4-4"></path>
				</svg>
			</div>
			<div>
				<strong>Accesso protetto</strong>
				<span>Sessione amministrativa</span>
			</div>
		</div>
	</aside>

	<main id="containers" class="main-content">
		<header class="topbar">
			<div class="breadcrumbs">
				<span>LabCtl</span><span class="crumb-slash">/</span>Amministrazione
			</div>
			<div class="topbar-right">
				<span
					class="live-indicator"
					class:live-error={overallHealth === 'error'}
					class:live-warning={overallHealth === 'warning'}
					class:live-loading={overallHealth === 'loading'}
				>
					<i></i>{overallHealth === 'ok'
						? 'Servizi operativi'
						: overallHealth === 'warning'
							? 'Modalità mock'
							: overallHealth === 'error'
								? 'Servizi degradati'
								: 'Verifica servizi…'}
				</span>
				<span class="avatar" aria-label="Amministratore">A</span>
			</div>
		</header>

		<section class="page-content">
			<div class="page-heading">
				<div>
					<div class="eyebrow">PANORAMICA INFRASTRUTTURA</div>
					<h1>Container registrati</h1>
					<p class="subtitle">Visualizza le registrazioni degli utenti e gestisci le rimozioni.</p>
				</div>
				<button
					class="button button-secondary refresh-button"
					onclick={() => void loadContainers()}
				>
					<svg viewBox="0 0 24 24" aria-hidden="true">
						<path
							d="M20 7v5h-5M4.6 9a7.5 7.5 0 0 1 12.6-2L20 12M4 17v-5h5m10.4 3a7.5 7.5 0 0 1-12.6 2L4 12"
						></path>
					</svg>
					Aggiorna
				</button>
			</div>

			<div class="summary-row">
				<div class="summary-card">
					<div class="summary-icon total-icon">
						<svg viewBox="0 0 24 24" aria-hidden="true">
							<rect x="4" y="4" width="16" height="6" rx="1.5"></rect>
							<rect x="4" y="14" width="16" height="6" rx="1.5"></rect>
							<path d="M8 7h.01M8 17h.01"></path>
						</svg>
					</div>
					<div>
						<span class="summary-label">Totale registrati</span>
						<strong class="summary-value">{total}</strong>
					</div>
					<span class="summary-note">nel registro</span>
				</div>
				<div class="summary-card">
					<div class="summary-icon network-icon">
						<svg viewBox="0 0 24 24" aria-hidden="true">
							<circle cx="12" cy="12" r="8"></circle>
							<path
								d="M4.5 12h15M12 4c2.2 2.2 3.2 4.9 3.2 8S14.2 17.8 12 20M12 4c-2.2 2.2-3.2 4.9-3.2 8s1 5.8 3.2 8"
							></path>
						</svg>
					</div>
					<div>
						<span class="summary-label">Endpoint autorizzati ora</span>
						<strong class="summary-value">
							{(networkLoading || networkError) && !networkState
								? '—'
								: (networkState?.authorized_endpoint_count ?? 0)}
						</strong>
					</div>
					<span class="summary-note">endpoint autorizzati</span>
				</div>
				<div class="summary-card">
					<div class="summary-icon connection-icon">
						<svg viewBox="0 0 24 24" aria-hidden="true">
							<path d="M7 7h3m4 0h3M7 17h3m4 0h3M5 5h2v4H5zm12 0h2v4h-2zM5 15h2v4H5zm12 0h2v4h-2z"
							></path>
							<path d="M10 7h4m-4 10h4"></path>
						</svg>
					</div>
					<div>
						<span class="summary-label">Connessioni attive</span>
						<strong class="summary-value">
							{(networkLoading || networkError) && !networkState
								? '—'
								: (networkState?.active_connection_count ?? 0)}
						</strong>
					</div>
					<span class="summary-note">conntrack</span>
				</div>
			</div>

			<div class="diagnostics-grid">
				<section class="diagnostic-panel" aria-labelledby="health-title">
					<div class="diagnostic-heading">
						<div>
							<h2 id="health-title">Salute dei servizi</h2>
							<p>Verifica API, database, fwdd e Proxmox.</p>
						</div>
						<button
							class="button button-secondary diagnostic-refresh"
							disabled={healthLoading}
							onclick={() => void loadSystemHealth()}
						>
							Aggiorna
						</button>
					</div>
					{#if healthError}
						<div class="diagnostic-error" role="alert">{healthError}</div>
					{/if}
					<div class="service-grid">
						{#if healthLoading && !health}
							<div class="diagnostic-empty">Verifica dei servizi…</div>
						{:else if health}
							{#each health.services as service (service.id)}
								<div class={`service-card service-${service.status}`}>
									<span class="service-dot"></span>
									<div class="service-copy">
										<strong>{service.label}</strong>
										<small>{service.detail}</small>
									</div>
									<span class="service-badge">{serviceStateLabel(service.status)}</span>
								</div>
							{/each}
						{:else}
							<div class="diagnostic-empty">Stato servizi non disponibile.</div>
						{/if}
					</div>
					<div class="diagnostic-footer">
						<span>
							{lastHealthUpdate
								? `Controllato ${new Intl.DateTimeFormat('it-IT', { timeStyle: 'medium' }).format(new Date(lastHealthUpdate))}`
								: ''}
						</span>
						{#if healthLoading}<span>Aggiornamento…</span>{/if}
					</div>
				</section>

				<section class="diagnostic-panel" aria-labelledby="drift-title">
					<div class="diagnostic-heading">
						<div>
							<h2 id="drift-title">Drift di provisioning</h2>
							<p>Confronto tra registro SQLite e stato nftables.</p>
						</div>
						<button
							class="button button-secondary diagnostic-refresh"
							disabled={driftLoading}
							onclick={() => void loadProvisioningDrift()}
						>
							Controlla
						</button>
					</div>
					{#if driftError}
						<div class="diagnostic-error" role="alert">{driftError}</div>
					{:else if driftLoading && !drift}
						<div class="diagnostic-empty">Verifica del drift…</div>
					{:else if drift}
						<div class="drift-summary" class:drift-summary-warning={!drift.in_sync}>
							<strong>{drift.in_sync ? 'Stato allineato' : 'Disallineamento rilevato'}</strong>
							<span>
								{driftCount === 0
									? 'Nessuna anomalia'
									: `${driftCount} ${driftCount === 1 ? 'anomalia' : 'anomalie'}`}
							</span>
						</div>

						{#if driftCount === 0}
							<p class="drift-empty">SQLite e nftables risultano allineati.</p>
						{:else}
							<div class="drift-list">
								{#if drift.kernel_drifted_items.length > 0}
									<h3>Endpoint attesi assenti da nftables</h3>
									{#each drift.kernel_drifted_items as item (`kernel-${item.vmid}`)}
										<div class="drift-item">
											<strong>CT-{item.vmid}</strong>
											<span>
												{item.expected[0]} · {item.expected[2]} · {item.expected[1]}
											</span>
										</div>
									{/each}
								{/if}
								{#if drift.db_pending_items.length > 0}
									<h3>Provisioning non sincronizzato nel database</h3>
									{#each drift.db_pending_items as item (`db-${item.vmid}`)}
										<div class="drift-item">
											<strong>CT-{item.vmid} · {item.actual_state}</strong>
											<span>
												Atteso: {item.desired_state} · {item.desired_vnet} · {item.desired_ip}
											</span>
											{#if item.last_error_msg}
												<small>{item.last_error_code}: {item.last_error_msg}</small>
											{/if}
										</div>
									{/each}
								{/if}
								{#if !drift.fwdd_in_sync && drift.kernel_drifted_items.length === 0}
									<p class="drift-empty">fwdd segnala un disallineamento senza dettagli.</p>
								{/if}
							</div>
						{/if}
						<div class="diagnostic-footer">
							<span>
								{`Controllato ${new Intl.DateTimeFormat('it-IT', { timeStyle: 'medium' }).format(new Date(drift.checked_at))}`}
							</span>
							{#if driftLoading}<span>Aggiornamento…</span>{/if}
						</div>
					{:else}
						<div class="diagnostic-empty">Verifica drift non disponibile.</div>
					{/if}
				</section>
			</div>

			<div class="table-panel">
				<div class="table-toolbar">
					<div>
						<h2>
							{activeTab === 'containers'
								? 'Registro container'
								: activeTab === 'authorized'
									? 'Endpoint autorizzati'
									: 'Connessioni attive'}
						</h2>
						<p>
							{activeTab === 'containers'
								? 'Registrazioni, prenotazioni IP e stato di provisioning.'
								: activeTab === 'authorized'
									? 'Endpoint presenti adesso nel set nftables autorizzato.'
									: 'Flussi conntrack correnti che coinvolgono endpoint autorizzati.'}
						</p>
					</div>
					<label class="search-box" class:search-hidden={activeTab !== 'containers'}>
						<svg viewBox="0 0 24 24" aria-hidden="true">
							<circle cx="10.8" cy="10.8" r="6.8"></circle>
							<path d="m16 16 4.5 4.5"></path>
						</svg>
						<input
							aria-label="Cerca container"
							placeholder="Cerca utente, VMID, IP..."
							value={search}
							oninput={onSearchInput}
							bind:this={searchInput}
						/>
						<kbd>⌘ K</kbd>
					</label>
				</div>

				{#if notice}
					<div class="notice notice-success" role="status">
						<span class="notice-icon">✓</span>
						{notice}
						<button class="notice-close" aria-label="Chiudi notifica" onclick={() => (notice = '')}
							>×</button
						>
					</div>
				{/if}

				{#if error}
					<div class="notice notice-error" role="alert">
						<span class="notice-icon">!</span>
						{error}
						<button class="notice-close" aria-label="Chiudi errore" onclick={() => (error = '')}
							>×</button
						>
					</div>
				{/if}

				<nav class="view-tabs" aria-label="Viste stato rete">
					<button
						class:tab-active={activeTab === 'containers'}
						aria-pressed={activeTab === 'containers'}
						onclick={() => (activeTab = 'containers')}
					>
						Container <span>{total}</span>
					</button>
					<button
						class:tab-active={activeTab === 'authorized'}
						aria-pressed={activeTab === 'authorized'}
						onclick={() => (activeTab = 'authorized')}
					>
						Autorizzati
						<span>
							{networkState?.authorized_endpoint_count ??
								(networkLoading || networkError ? '…' : 0)}
						</span>
					</button>
					<button
						class:tab-active={activeTab === 'connections'}
						aria-pressed={activeTab === 'connections'}
						onclick={() => (activeTab = 'connections')}
					>
						Connessioni attive
						<span>
							{networkState?.active_connection_count ?? (networkLoading || networkError ? '…' : 0)}
						</span>
					</button>
				</nav>

				{#if networkError && activeTab !== 'containers'}
					<div class="notice notice-error" role="alert">
						<span class="notice-icon">!</span>
						{networkError}
						<button
							class="notice-close"
							aria-label="Riprova stato rete"
							onclick={() => void loadNetworkState()}>↻</button
						>
					</div>
				{/if}

				<div class="table-scroll">
					{#if activeTab === 'containers'}
						<table>
							<thead>
								<tr>
									<th>CONTAINER</th>
									<th>UTENTE</th>
									<th>CLASSE</th>
									<th>INDIRIZZO IP</th>
									<th>STATO</th>
									<th>REGISTRATO</th>
									<th><span class="sr-only">Azioni</span></th>
								</tr>
							</thead>
							<tbody>
								{#if loading && containers.length === 0}
									{#each [0, 1, 2, 3] as skeleton (skeleton)}
										<tr class="skeleton-row">
											<td colspan="7"><span></span></td>
										</tr>
									{/each}
								{:else if error && containers.length === 0}
									<tr>
										<td colspan="7">
											<div class="empty-state">
												<strong>Dati non disponibili</strong>
												<span>Verifica la connessione e riprova.</span>
												<button
													class="button button-secondary"
													onclick={() => void loadContainers()}>Riprova</button
												>
											</div>
										</td>
									</tr>
								{:else if containers.length === 0}
									<tr>
										<td colspan="7">
											<div class="empty-state">
												<div class="empty-icon">
													<svg viewBox="0 0 24 24" aria-hidden="true">
														<rect x="4" y="4" width="16" height="6" rx="1.5"></rect>
														<rect x="4" y="14" width="16" height="6" rx="1.5"></rect>
													</svg>
												</div>
												<strong
													>{search ? 'Nessun risultato' : 'Nessun container registrato'}</strong
												>
												<span>
													{search
														? 'Prova a modificare i termini della ricerca.'
														: 'I container registrati dagli utenti appariranno qui.'}
												</span>
											</div>
										</td>
									</tr>
								{:else}
									{#each containers as container (container.vmid)}
										<tr>
											<td>
												<div class="container-cell">
													<span class="container-glyph">
														<svg viewBox="0 0 24 24" aria-hidden="true">
															<path d="M12 3.5 20 8v8l-8 4.5L4 16V8l8-4.5Z"></path>
															<path d="m4.5 8.3 7.5 4.2 7.5-4.2M12 12.5v7.7"></path>
														</svg>
													</span>
													<span>
														<strong>{container.hostname_hint || `CT-${container.vmid}`}</strong>
														<small
															>VMID {container.vmid}{container.pve_node
																? ` · ${container.pve_node}`
																: ''}</small
														>
													</span>
												</div>
											</td>
											<td>
												<div class="user-cell">
													<strong>{container.display_name || container.username}</strong>
													<small>@{container.username}</small>
												</div>
											</td>
											<td><span class="class-tag">{container.class_code}</span></td>
											<td>
												<div class="ip-cell">
													<strong>{container.reserved_ip || '—'}</strong>
													<small>{container.vnet_name}</small>
												</div>
											</td>
											<td>
												<span class={`status-pill ${stateClass(container)}`}>
													<i></i>{stateLabel(container)}
												</span>
											</td>
											<td class="date-cell">{formatDate(container.created_at)}</td>
											<td class="actions-cell">
												<button
													class="delete-button"
													aria-label={`Elimina container ${container.vmid}`}
													title="Elimina container"
													onclick={() => openDeleteDialog(container)}
												>
													<svg viewBox="0 0 24 24" aria-hidden="true">
														<path d="M4 7h16M10 11v6m4-6v6M6.5 7l.8 13h9.4l.8-13M9 7V4h6v3"></path>
													</svg>
												</button>
											</td>
										</tr>
									{/each}
								{/if}
							</tbody>
						</table>
					{:else if activeTab === 'authorized'}
						<table>
							<thead>
								<tr>
									<th>ENDPOINT / CONTAINER</th>
									<th>UTENTE</th>
									<th>CLASSE</th>
									<th>INDIRIZZO IP</th>
									<th>MAC ADDRESS</th>
									<th>VNET</th>
								</tr>
							</thead>
							<tbody>
								{#if networkLoading && !networkState}
									<tr class="skeleton-row"><td colspan="6"><span></span></td></tr>
								{:else if networkError && !networkState}
									<tr>
										<td colspan="6">
											<div class="empty-state">
												<strong>Stato rete non disponibile</strong>
												<button
													class="button button-secondary"
													onclick={() => void loadNetworkState()}>Riprova</button
												>
											</div>
										</td>
									</tr>
								{:else if networkState?.authorized_endpoints.length}
									{#each networkState.authorized_endpoints as endpoint (`${endpoint.vnet}-${endpoint.mac_address}-${endpoint.ip}`)}
										<tr>
											<td>
												<div class="container-cell">
													<span class="container-glyph">
														<svg viewBox="0 0 24 24" aria-hidden="true">
															<path d="M12 3.5 20 8v8l-8 4.5L4 16V8l8-4.5Z"></path>
															<path d="m4.5 8.3 7.5 4.2 7.5-4.2M12 12.5v7.7"></path>
														</svg>
													</span>
													<span>
														<strong>
															{endpoint.container?.hostname_hint ||
																(endpoint.container
																	? `CT-${endpoint.container.vmid}`
																	: 'Non registrato')}
														</strong>
														<small
															>{endpoint.container
																? `VMID ${endpoint.container.vmid}`
																: 'Presente nel set nftables'}</small
														>
													</span>
												</div>
											</td>
											<td>
												<div class="user-cell">
													<strong>{endpoint.container?.display_name || '—'}</strong>
													<small
														>{endpoint.container ? `@${endpoint.container.username}` : '—'}</small
													>
												</div>
											</td>
											<td><span class="class-tag">{endpoint.container?.class_code || '—'}</span></td
											>
											<td class="mono-cell">{endpoint.ip}</td>
											<td class="mono-cell">{endpoint.mac_address}</td>
											<td><span class="class-tag">{endpoint.vnet}</span></td>
										</tr>
									{/each}
								{:else}
									<tr
										><td colspan="6"
											><div class="empty-state">
												<strong>Nessun endpoint autorizzato</strong><span
													>Il set nftables è vuoto.</span
												>
											</div></td
										></tr
									>
								{/if}
							</tbody>
						</table>
					{:else}
						<table>
							<thead>
								<tr>
									<th>PROTOCOLLO / STATO</th>
									<th>ORIGINE</th>
									<th>DESTINAZIONE</th>
									<th>FAMIGLIA</th>
									<th>FLAGS</th>
								</tr>
							</thead>
							<tbody>
								{#if networkLoading && !networkState}
									<tr class="skeleton-row"><td colspan="5"><span></span></td></tr>
								{:else if networkError && !networkState}
									<tr>
										<td colspan="5">
											<div class="empty-state">
												<strong>Stato rete non disponibile</strong>
												<button
													class="button button-secondary"
													onclick={() => void loadNetworkState()}>Riprova</button
												>
											</div>
										</td>
									</tr>
								{:else if networkState?.active_connections.length}
									{#each networkState.active_connections as connection, index (`${connection.protocol}-${connection.source_ip}-${connection.source_port}-${connection.destination_ip}-${connection.destination_port}-${index}`)}
										<tr>
											<td>
												<div class="user-cell">
													<strong>{connection.protocol}</strong>
													<small>{connection.state}</small>
												</div>
											</td>
											<td class="mono-cell">{connectionPeer(connection, 'source')}</td>
											<td class="mono-cell">{connectionPeer(connection, 'destination')}</td>
											<td><span class="class-tag">{connection.family}</span></td>
											<td>
												<span
													class="status-pill"
													class:state-good={connection.assured}
													class:state-pending={!connection.assured}
												>
													<i></i>{connection.assured
														? 'ASSURED'
														: connection.unreplied
															? 'UNREPLIED'
															: 'ACTIVE'}
												</span>
											</td>
										</tr>
									{/each}
								{:else}
									<tr
										><td colspan="5"
											><div class="empty-state">
												<strong>Nessuna connessione attiva</strong><span
													>Non risultano flussi conntrack per gli endpoint autorizzati.</span
												>
											</div></td
										></tr
									>
								{/if}
							</tbody>
						</table>
					{/if}
				</div>

				<footer class="table-footer">
					<span>
						{#if activeTab === 'containers' && total > 0}
							Visualizzati <strong>{rangeStart}–{rangeEnd}</strong> di <strong>{total}</strong>
							container
						{:else if activeTab === 'authorized' && networkState}
							<strong>{networkState.authorized_endpoint_count}</strong> endpoint correnti
						{:else if activeTab === 'connections' && networkState}
							<strong>{networkState.active_connection_count}</strong> flussi
							{#if networkState.connections_truncated}<span> · elenco limitato a 500</span>{/if}
						{:else}
							<span>
								{activeTab === 'containers'
									? 'Nessun container da visualizzare'
									: networkLoading
										? 'Aggiornamento stato rete…'
										: 'Nessun elemento da visualizzare'}
							</span>
						{/if}
					</span>
					{#if activeTab === 'containers'}
						<div class="pagination">
							<button
								class="page-button"
								aria-label="Pagina precedente"
								disabled={page <= 1 || loading}
								onclick={() => {
									offset = Math.max(0, offset - pageSize);
									void loadContainers();
								}}
							>
								‹
							</button>
							<span>Pagina <strong>{page}</strong> di <strong>{pageCount}</strong></span>
							<button
								class="page-button"
								aria-label="Pagina successiva"
								disabled={page >= pageCount || loading}
								onclick={() => {
									offset += pageSize;
									void loadContainers();
								}}
							>
								›
							</button>
						</div>
					{:else}
						<span class="network-observed">
							{lastNetworkUpdate
								? `Rilevato ${new Intl.DateTimeFormat('it-IT', { timeStyle: 'medium' }).format(new Date(lastNetworkUpdate))}`
								: ''}
						</span>
					{/if}
				</footer>
			</div>

			<div class="page-footnote">
				<span class="footnote-dot"></span>
				Le modifiche vengono applicate al registro e sincronizzate con il firewall.
			</div>
		</section>
	</main>
</div>

{#if pendingDelete}
	<div
		class="modal-backdrop"
		role="presentation"
		onclick={(event) => {
			if (event.target === event.currentTarget && !deleting) pendingDelete = null;
		}}
		onkeydown={(event) => {
			if (event.key === 'Escape' && !deleting) pendingDelete = null;
		}}
	>
		<div
			class="confirm-dialog"
			role="alertdialog"
			aria-modal="true"
			aria-labelledby="delete-title"
			aria-describedby="delete-description"
			tabindex="-1"
		>
			<div class="dialog-icon">
				<svg viewBox="0 0 24 24" aria-hidden="true">
					<path d="M12 3.5 21 20H3l9-16.5Z"></path>
					<path d="M12 9v4m0 3h.01"></path>
				</svg>
			</div>
			<h2 id="delete-title">Eliminare il container?</h2>
			<p id="delete-description">
				Stai per rimuovere <strong
					>{pendingDelete.hostname_hint || `CT-${pendingDelete.vmid}`}</strong
				>
				(VMID {pendingDelete.vmid}) dal registro LabCtl. La prenotazione IP e lo stato firewall
				verranno revocati. Questa azione non elimina la macchina da Proxmox.
			</p>
			<div class="dialog-actions">
				<button
					class="button button-secondary"
					disabled={deleting}
					onclick={() => (pendingDelete = null)}>Annulla</button
				>
				<button
					class="button button-danger"
					disabled={deleting}
					onclick={() => void confirmDelete()}
				>
					{#if deleting}
						<span class="spinner"></span> Rimozione...
					{:else}
						Elimina dal registro
					{/if}
				</button>
			</div>
		</div>
	</div>
{/if}
