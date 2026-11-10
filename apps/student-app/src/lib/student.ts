export interface StudentReservation {
	vmid: number;
	reserved_ip: string;
	mac_address: string | null;
	pve_node: string | null;
	vnet_name: string;
	hostname_hint: string | null;
	stato_prenotaz: string;
	actual_state: string;
	last_verified_at: string | null;
}

export interface StudentNetwork {
	username: string;
	display_name: string;
	class_code: string;
	vnet_name: string;
	max_active_containers: number;
	active_containers_count: number;
	subnet_29: {
		cidr: string;
		netmask: string;
		prefixlen: number;
		network_ip: string;
		gateway_ip: string;
		broadcast_ip: string;
		usable_student_ips: string[];
		free_student_ips: string[];
	};
	reservations: StudentReservation[];
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

export function getMyNetwork() {
	return request<StudentNetwork>('/api/student/me/network');
}

export function createReservation(payload: { vmid: number; reserved_ip: string }) {
	return request<StudentReservation>('/api/student/reservations', {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify(payload)
	});
}

export function deleteReservation(vmid: number) {
	return request<{ status: string; vmid: number }>(`/api/student/reservations/${vmid}`, {
		method: 'DELETE'
	});
}
