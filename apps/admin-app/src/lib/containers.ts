export interface ContainerRecord {
	vmid: number;
	hostname_hint: string | null;
	pve_node: string | null;
	mac_address: string | null;
	vnet_name: string;
	is_enabled: number;
	created_at: string;
	username: string;
	display_name: string;
	class_code: string;
	reserved_ip: string | null;
	stato_prenotaz: string | null;
	actual_state: string | null;
	last_verified_at: string | null;
}

interface ContainerListResponse {
	items: ContainerRecord[];
	total: number;
	limit: number;
	offset: number;
}

export interface AuthorizedEndpoint {
	vnet: string;
	mac_address: string;
	ip: string;
	container: {
		vmid: number;
		hostname_hint: string | null;
		username: string;
		display_name: string;
		class_code: string;
	} | null;
}

export interface ActiveConnection {
	family: string;
	protocol: string;
	state: string;
	source_ip: string;
	destination_ip: string;
	source_port?: number;
	destination_port?: number;
	assured: boolean;
	unreplied: boolean;
	source_container: AuthorizedEndpoint['container'];
	destination_container: AuthorizedEndpoint['container'];
}

export interface NetworkState {
	authorized_endpoints: AuthorizedEndpoint[];
	authorized_endpoint_count: number;
	active_connections: ActiveConnection[];
	active_connection_count: number;
	connections_truncated: boolean;
	observed_at: string;
}

async function request<T>(url: string, init?: RequestInit): Promise<T> {
	const response = await fetch(url, {
		...init,
		headers: {
			Accept: 'application/json',
			...(init?.headers ?? {})
		}
	});

	if (!response.ok) {
		let message = `Richiesta non riuscita (${response.status}).`;
		try {
			const body = (await response.json()) as { detail?: unknown; message?: string };
			if (typeof body.detail === 'string') message = body.detail;
			else if (typeof body.message === 'string') message = body.message;
		} catch {
			// Keep the HTTP status message when the response is not JSON.
		}
		throw new Error(message);
	}

	return response.json() as Promise<T>;
}

export function listContainers(params: { search: string; limit: number; offset: number }) {
	const query = new URLSearchParams({
		search: params.search,
		limit: String(params.limit),
		offset: String(params.offset)
	});
	return request<ContainerListResponse>(`/api/admin/containers?${query}`);
}

export function getNetworkState() {
	return request<NetworkState>('/api/admin/network-state');
}

export function deleteContainer(vmid: number) {
	return request<{ status: string; vmid: number }>(`/api/admin/containers/${vmid}`, {
		method: 'DELETE'
	});
}
