<script lang="ts">
	import { resolve } from '$app/paths';
	import { onMount } from 'svelte';
	import {
		createReservation,
		deleteReservation,
		getMyNetwork,
		type StudentNetwork
	} from '#lib/student.js';

	let network = $state<StudentNetwork | null>(null);
	let loading = $state(true);
	let submitting = $state(false);
	let deletingVmid = $state<number | null>(null);
	let error = $state('');
	let notice = $state('');
	let selectedIp = $state('');
	let vmidValue = $state('');

	const availableIps = $derived(network?.subnet_29.free_student_ips ?? []);

	onMount(() => {
		void refresh();
	});

	async function refresh() {
		loading = true;
		error = '';
		try {
			network = await getMyNetwork();
			if (!availableIps.includes(selectedIp)) {
				selectedIp = availableIps[0] ?? '';
			}
		} catch (cause) {
			error = cause instanceof Error ? cause.message : 'Impossibile caricare la rete assegnata.';
		} finally {
			loading = false;
		}
	}

	async function submitReservation(event: SubmitEvent) {
		event.preventDefault();
		const vmid = Number(vmidValue);
		if (!Number.isInteger(vmid) || vmid < 100) {
			error = 'Inserisci un VMID valido (almeno 100).';
			return;
		}
		if (!selectedIp) {
			error = 'Non ci sono indirizzi IP liberi da assegnare.';
			return;
		}

		submitting = true;
		error = '';
		notice = '';
		try {
			const reservation = await createReservation({ vmid, reserved_ip: selectedIp });
			notice =
				reservation.actual_state === 'SYNCED'
					? `VMID ${vmid} associato a ${selectedIp}; regola di rete attiva.`
					: `Associazione salvata per VMID ${vmid}; la configurazione di rete è in attesa di sincronizzazione.`;
			vmidValue = '';
			await refresh();
		} catch (cause) {
			error = cause instanceof Error ? cause.message : 'Impossibile associare il container.';
		} finally {
			submitting = false;
		}
	}

	async function removeReservation(vmid: number) {
		if (!window.confirm(`Rimuovere l'associazione del VMID ${vmid}?`)) return;
		deletingVmid = vmid;
		error = '';
		notice = '';
		try {
			await deleteReservation(vmid);
			notice = `Associazione del VMID ${vmid} rimossa.`;
			await refresh();
		} catch (cause) {
			error = cause instanceof Error ? cause.message : 'Impossibile rimuovere l’associazione.';
		} finally {
			deletingVmid = null;
		}
	}

	function stateLabel(state: string) {
		switch (state) {
			case 'SYNCED':
				return 'Attivo';
			case 'DRIFTED':
				return 'In sincronizzazione';
			case 'ERROR':
				return 'Errore';
			case 'ABSENT':
				return 'Non attivo';
			default:
				return 'In verifica';
		}
	}
</script>

<svelte:head>
	<title>La mia rete · LabCtl</title>
	<meta
		name="description"
		content="Visualizza la tua rete di laboratorio e associa i container Proxmox ai tuoi indirizzi IP."
	/>
</svelte:head>

<main class="page-shell">
	<header class="topbar">
		<a class="brand" href={resolve('/', {})} aria-label="LabCtl - pagina iniziale">
			<span class="brand-mark">L</span>
			<span>LabCtl <small>STUDENTI</small></span>
		</a>
		<span class="secure-label"><span></span> Accesso autenticato</span>
	</header>

	<section class="intro">
		<p class="eyebrow">AREA STUDENTE</p>
		<h1>La tua rete di laboratorio</h1>
		<p class="subtitle">
			La tua sottorete resta assegnata al tuo account. Collega ogni IP a un container LXC del tuo
			pool Proxmox.
		</p>
	</section>

	{#if notice}
		<div class="message success" role="status">{notice}</div>
	{/if}

	{#if error}
		<div class="message error" role="alert">
			<span>{error}</span>
			<button class="text-button" type="button" onclick={() => void refresh()}>Riprova</button>
		</div>
	{/if}

	{#if loading}
		<section class="panel loading-panel" aria-live="polite">
			<span class="spinner"></span>
			<p>Caricamento della rete assegnata…</p>
		</section>
	{:else if network}
		<section class="summary-grid" aria-label="Parametri di rete">
			<article class="summary-card subnet-card">
				<p class="card-label">SOTTORETE ASSEGNATA</p>
				<strong>{network.subnet_29.cidr}</strong>
				<span>Maschera {network.subnet_29.netmask}</span>
			</article>
			<article class="summary-card">
				<p class="card-label">GATEWAY</p>
				<strong>{network.subnet_29.gateway_ip}</strong>
				<span>Indirizzo riservato alla rete</span>
			</article>
			<article class="summary-card">
				<p class="card-label">CLASSE · RETE</p>
				<strong>{network.class_code || '—'}</strong>
				<span>{network.vnet_name || 'VNet non configurata'}</span>
			</article>
		</section>

		<section class="panel address-panel">
			<div class="section-heading">
				<div>
					<p class="eyebrow">INDIRIZZI UTILIZZABILI</p>
					<h2>I tuoi IP</h2>
				</div>
				<span class="count-pill">
					{network.active_containers_count} / {network.max_active_containers} container attivi
				</span>
			</div>

			<div class="address-list">
				{#each network.subnet_29.usable_student_ips as ip (ip)}
					{@const reservation = network.reservations.find(
						(item) => item.reserved_ip === ip && item.stato_prenotaz === 'ACTIVE'
					)}
					<article class:occupied={Boolean(reservation)} class="address-row">
						<div class="address-icon" aria-hidden="true">{reservation ? '↗' : '+'}</div>
						<div class="address-details">
							<strong>{ip}</strong>
							{#if reservation}
								<span>
									VMID {reservation.vmid} · {reservation.hostname_hint || 'Container Proxmox'}
								</span>
							{:else}
								<span>Disponibile</span>
							{/if}
						</div>
						{#if reservation}
							<div class="reservation-actions">
								<span class:state-active={reservation.actual_state === 'SYNCED'} class="state-pill">
									{stateLabel(reservation.actual_state)}
								</span>
								<button
									class="remove-button"
									type="button"
									disabled={deletingVmid === reservation.vmid}
									onclick={() => void removeReservation(reservation.vmid)}
								>
									{deletingVmid === reservation.vmid ? 'Rimozione…' : 'Rimuovi'}
								</button>
							</div>
						{:else}
							<span class="free-pill">Libero</span>
						{/if}
					</article>
				{/each}
			</div>
			<p class="footnote">
				Network address, broadcast e gateway non sono assegnabili ai container.
			</p>
		</section>

		<section class="panel connect-panel">
			<div class="section-heading">
				<div>
					<p class="eyebrow">REGISTRAZIONE CONTAINER</p>
					<h2>Associa un IP a un VMID</h2>
				</div>
			</div>
			<p class="form-intro">
				Inserisci il VMID di un container appartenente al tuo pool Proxmox. Il sistema ne verifica
				pool, rete e interfaccia prima di attivare l’indirizzo.
			</p>
			<form class="reservation-form" onsubmit={submitReservation}>
				<label>
					<span>Indirizzo IP libero</span>
					<select bind:value={selectedIp} required disabled={availableIps.length === 0}>
						{#if availableIps.length === 0}
							<option value="">Nessun IP libero</option>
						{:else}
							{#each availableIps as ip (ip)}
								<option value={ip}>{ip}</option>
							{/each}
						{/if}
					</select>
				</label>
				<label>
					<span>VMID Proxmox</span>
					<input
						bind:value={vmidValue}
						type="number"
						min="100"
						max="999999999"
						step="1"
						placeholder="Es. 10401"
						required
					/>
				</label>
				<button
					class="primary-button"
					type="submit"
					disabled={submitting ||
						availableIps.length === 0 ||
						network.active_containers_count >= network.max_active_containers}
				>
					{submitting ? 'Verifica in corso…' : 'Verifica e associa'}
				</button>
			</form>
			<p class="footnote">
				Non condividere credenziali Proxmox: l’associazione verifica il container tramite il
				servizio LabCtl.
			</p>
		</section>
	{/if}

	<footer>
		<span>LabCtl · Rete di laboratorio</span>
		<span>Le configurazioni sono applicate dal firewall di laboratorio.</span>
	</footer>
</main>

<style>
	:global(body) {
		margin: 0;
		background: #f3f6fa;
		color: #15263e;
		font-family:
			Inter,
			ui-sans-serif,
			system-ui,
			-apple-system,
			BlinkMacSystemFont,
			'Segoe UI',
			sans-serif;
	}

	:global(*) {
		box-sizing: border-box;
	}

	.page-shell {
		max-width: 1080px;
		min-height: 100vh;
		margin: 0 auto;
		padding: 0 32px 48px;
	}

	.topbar {
		display: flex;
		height: 78px;
		align-items: center;
		justify-content: space-between;
		border-bottom: 1px solid #e1e8f0;
	}

	.brand {
		display: inline-flex;
		align-items: center;
		gap: 11px;
		color: #142a47;
		font-size: 17px;
		font-weight: 750;
		text-decoration: none;
	}

	.brand small {
		margin-left: 7px;
		color: #67809e;
		font-size: 10px;
		font-weight: 700;
		letter-spacing: 0.1em;
	}

	.brand-mark {
		display: grid;
		width: 34px;
		height: 34px;
		place-items: center;
		border-radius: 10px;
		background: #1768d2;
		color: white;
		font-size: 18px;
	}

	.secure-label {
		display: inline-flex;
		align-items: center;
		gap: 8px;
		color: #5c718a;
		font-size: 13px;
	}

	.secure-label span {
		width: 8px;
		height: 8px;
		border-radius: 50%;
		background: #27a36a;
	}

	.intro {
		padding: 42px 0 24px;
	}

	.eyebrow,
	.card-label {
		margin: 0 0 8px;
		color: #66809e;
		font-size: 10px;
		font-weight: 750;
		letter-spacing: 0.13em;
	}

	h1,
	h2,
	p {
		margin-top: 0;
	}

	h1 {
		margin-bottom: 9px;
		color: #102744;
		font-size: clamp(27px, 4vw, 36px);
		letter-spacing: -0.035em;
	}

	.subtitle {
		max-width: 690px;
		margin-bottom: 0;
		color: #5b6f87;
		font-size: 15px;
		line-height: 1.65;
	}

	.summary-grid {
		display: grid;
		grid-template-columns: 1.3fr 1fr 1fr;
		gap: 15px;
		margin-bottom: 18px;
	}

	.summary-card,
	.panel {
		border: 1px solid #e2e9f1;
		border-radius: 15px;
		background: #fff;
		box-shadow: 0 4px 18px rgb(26 53 84 / 4%);
	}

	.summary-card {
		display: flex;
		min-height: 125px;
		flex-direction: column;
		justify-content: center;
		padding: 19px 22px;
	}

	.summary-card strong {
		margin: 2px 0 7px;
		color: #14365e;
		font-size: 23px;
		letter-spacing: -0.025em;
	}

	.summary-card span {
		color: #72849a;
		font-size: 12px;
	}

	.subnet-card {
		border-color: #cee0f7;
		background: linear-gradient(115deg, #fff, #f3f8ff);
	}

	.panel {
		margin-bottom: 18px;
		padding: 25px;
	}

	.section-heading {
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: 14px;
		margin-bottom: 17px;
	}

	.section-heading .eyebrow {
		margin-bottom: 5px;
	}

	h2 {
		margin-bottom: 0;
		color: #17304f;
		font-size: 20px;
		letter-spacing: -0.02em;
	}

	.count-pill,
	.free-pill,
	.state-pill {
		display: inline-flex;
		align-items: center;
		border-radius: 999px;
		font-size: 11px;
		font-weight: 650;
		white-space: nowrap;
	}

	.count-pill {
		padding: 8px 11px;
		background: #f0f5fb;
		color: #4f6783;
	}

	.address-list {
		display: grid;
		gap: 9px;
	}

	.address-row {
		display: flex;
		min-height: 66px;
		align-items: center;
		gap: 13px;
		padding: 10px 13px;
		border: 1px solid #e8edf3;
		border-radius: 10px;
		background: #fbfcfe;
	}

	.address-row.occupied {
		border-color: #dce8f6;
		background: #f7faff;
	}

	.address-icon {
		display: grid;
		width: 34px;
		height: 34px;
		flex: 0 0 auto;
		place-items: center;
		border-radius: 9px;
		background: #eaf3ff;
		color: #246bc0;
		font-size: 18px;
		font-weight: 700;
	}

	.address-details {
		display: grid;
		flex: 1;
		gap: 4px;
	}

	.address-details strong {
		color: #1c3859;
		font-size: 14px;
		font-variant-numeric: tabular-nums;
	}

	.address-details span,
	.footnote {
		color: #75869a;
		font-size: 11px;
	}

	.free-pill {
		padding: 6px 9px;
		background: #e9f7ef;
		color: #27794c;
	}

	.reservation-actions {
		display: flex;
		align-items: center;
		gap: 12px;
	}

	.state-pill {
		padding: 6px 9px;
		background: #fff4dc;
		color: #9a6a13;
	}

	.state-pill.state-active {
		background: #e9f7ef;
		color: #27794c;
	}

	.remove-button,
	.text-button {
		border: 0;
		background: transparent;
		color: #9b5260;
		cursor: pointer;
		font: inherit;
		font-size: 12px;
	}

	.remove-button:disabled {
		cursor: wait;
		opacity: 0.6;
	}

	.footnote {
		margin: 14px 0 0;
		line-height: 1.55;
	}

	.form-intro {
		margin: -3px 0 19px;
		color: #657990;
		font-size: 13px;
		line-height: 1.6;
	}

	.reservation-form {
		display: grid;
		grid-template-columns: minmax(180px, 1fr) minmax(180px, 1fr) auto;
		align-items: end;
		gap: 13px;
	}

	label {
		display: grid;
		gap: 7px;
		color: #435b76;
		font-size: 12px;
		font-weight: 650;
	}

	input,
	select {
		width: 100%;
		min-height: 43px;
		padding: 0 12px;
		border: 1px solid #d5dfeb;
		border-radius: 8px;
		background: white;
		color: #183453;
		font: inherit;
		font-size: 13px;
	}

	input:focus,
	select:focus {
		border-color: #4283d0;
		outline: 3px solid rgb(66 131 208 / 15%);
	}

	.primary-button {
		min-height: 43px;
		padding: 0 17px;
		border: 0;
		border-radius: 8px;
		background: #1768d2;
		color: white;
		cursor: pointer;
		font: inherit;
		font-size: 12px;
		font-weight: 700;
		white-space: nowrap;
	}

	.primary-button:hover:not(:disabled) {
		background: #1058b7;
	}

	.primary-button:disabled {
		cursor: not-allowed;
		opacity: 0.52;
	}

	.message {
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: 12px;
		margin-bottom: 16px;
		padding: 12px 15px;
		border: 1px solid;
		border-radius: 9px;
		font-size: 13px;
	}

	.message.success {
		border-color: #bde4cc;
		background: #f0faf4;
		color: #276a43;
	}

	.message.error {
		border-color: #f0c8cc;
		background: #fff5f5;
		color: #943d48;
	}

	.message .text-button {
		color: inherit;
		font-weight: 700;
	}

	.loading-panel {
		display: flex;
		min-height: 170px;
		align-items: center;
		justify-content: center;
		gap: 12px;
		color: #637a94;
	}

	.loading-panel p {
		margin: 0;
		font-size: 13px;
	}

	.spinner {
		width: 17px;
		height: 17px;
		border: 2px solid #cfe0f4;
		border-top-color: #1768d2;
		border-radius: 50%;
		animation: spin 0.75s linear infinite;
	}

	@keyframes spin {
		to {
			transform: rotate(360deg);
		}
	}

	footer {
		display: flex;
		justify-content: space-between;
		gap: 16px;
		padding: 12px 2px;
		color: #7d8da0;
		font-size: 10px;
	}

	@media (max-width: 760px) {
		.page-shell {
			padding: 0 18px 34px;
		}

		.summary-grid {
			grid-template-columns: 1fr 1fr;
		}

		.subnet-card {
			grid-column: 1 / -1;
		}

		.reservation-form {
			grid-template-columns: 1fr 1fr;
		}

		.primary-button {
			grid-column: 1 / -1;
		}
	}

	@media (max-width: 520px) {
		.topbar {
			height: 66px;
		}

		.secure-label {
			font-size: 0;
		}

		.secure-label span {
			width: 9px;
			height: 9px;
		}

		.intro {
			padding-top: 32px;
		}

		.summary-grid {
			grid-template-columns: 1fr;
		}

		.subnet-card {
			grid-column: auto;
		}

		.panel {
			padding: 19px 15px;
		}

		.section-heading {
			align-items: flex-start;
			flex-direction: column;
		}

		.address-row {
			gap: 9px;
			padding: 9px;
		}

		.reservation-actions {
			align-items: flex-end;
			flex-direction: column;
			gap: 5px;
		}

		.reservation-form {
			grid-template-columns: 1fr;
		}

		.primary-button {
			grid-column: auto;
		}

		footer {
			flex-direction: column;
		}
	}
</style>
