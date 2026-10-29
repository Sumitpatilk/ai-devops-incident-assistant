import { afterEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import App from '../App'

function makeIncident(
  id: number,
  status: 'not_run' | 'passed' | 'failed' = 'failed',
  logs = `OOMKilled incident ${id}`,
) {
  return {
    id,
    source: 'kubernetes',
    logs,
    analysis_json: '{}',
    verification_status: status,
    verification_notes: null,
    fix_description: null,
    created_at: '2026-10-28T10:00:00',
    verified_at: null,
  }
}

function jsonResponse(body: unknown, status = 200): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: async () => body,
    text: async () => JSON.stringify(body),
  } as Response
}

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

describe('incident history filters', () => {
  it('searches incidents and sends the search term to the API', async () => {
    const requestedUrls: string[] = []
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input)
      requestedUrls.push(url)

      if (url === '/health') return jsonResponse({ status: 'ok' })
      if (url === '/api/v1/auth/me') {
        return jsonResponse({ authenticated: true, username: 'test-user' })
      }
      if (url === '/api/v1/incidents?limit=50&offset=0') {
        return jsonResponse({ items: [], limit: 50, offset: 0 })
      }
      if (url === '/api/v1/incidents?limit=50&offset=0&search=OOMKilled') {
        return jsonResponse({
          items: [makeIncident(7, 'failed', 'OOMKilled in production pod')],
          limit: 50,
          offset: 0,
        })
      }
      return jsonResponse({ detail: `Unexpected request: ${url}` }, 404)
    })

    vi.stubGlobal('fetch', fetchMock)
    render(<App />)

    const searchInput = await screen.findByRole('searchbox', {
      name: 'Search source or logs',
    })
    fireEvent.change(searchInput, { target: { value: 'OOMKilled' } })
    fireEvent.click(screen.getByRole('button', { name: 'Search' }))

    await waitFor(() => {
      expect(screen.getByRole('button', { name: 'Open incident 7' })).toBeTruthy()
    })

    expect(requestedUrls).toContain(
      '/api/v1/incidents?limit=50&offset=0&search=OOMKilled',
    )
  })

  it('filters by verification status and clears filters', async () => {
    const requestedUrls: string[] = []
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input)
      requestedUrls.push(url)

      if (url === '/health') return jsonResponse({ status: 'ok' })
      if (url === '/api/v1/auth/me') {
        return jsonResponse({ authenticated: true, username: 'test-user' })
      }
      if (
        url === '/api/v1/incidents?limit=50&offset=0' ||
        url === '/api/v1/incidents?limit=50&offset=0&verification_status=failed'
      ) {
        return jsonResponse({
          items: [makeIncident(9, 'failed')],
          limit: 50,
          offset: 0,
        })
      }
      return jsonResponse({ detail: `Unexpected request: ${url}` }, 404)
    })

    vi.stubGlobal('fetch', fetchMock)
    render(<App />)

    const statusFilter = await screen.findByRole('combobox', {
      name: 'Verification status',
    })
    fireEvent.change(statusFilter, { target: { value: 'failed' } })
    fireEvent.click(screen.getByRole('button', { name: 'Search' }))

    await waitFor(() => {
      expect(requestedUrls).toContain(
        '/api/v1/incidents?limit=50&offset=0&verification_status=failed',
      )
    })

    fireEvent.click(screen.getByRole('button', { name: 'Clear filters' }))

    await waitFor(() => {
      expect(requestedUrls.filter(
        (url) => url === '/api/v1/incidents?limit=50&offset=0',
      ).length).toBeGreaterThanOrEqual(2)
    })

    expect((statusFilter as HTMLSelectElement).value).toBe('all')
  })


  it('keeps pagination on the applied status until Search is submitted', async () => {
    const requestedUrls: string[] = []
    const firstPage = Array.from({ length: 50 }, (_, index) =>
      makeIncident(index + 1, 'failed'),
    )
    const nextPage = [makeIncident(51, 'failed')]

    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input)
      requestedUrls.push(url)

      if (url === '/health') return jsonResponse({ status: 'ok' })
      if (url === '/api/v1/auth/me') {
        return jsonResponse({ authenticated: true, username: 'test-user' })
      }
      if (url === '/api/v1/incidents?limit=50&offset=0') {
        return jsonResponse({ items: firstPage, limit: 50, offset: 0 })
      }
      if (url === '/api/v1/incidents?limit=50&offset=50') {
        return jsonResponse({ items: nextPage, limit: 50, offset: 50 })
      }
      return jsonResponse({ detail: `Unexpected request: ${url}` }, 404)
    })

    vi.stubGlobal('fetch', fetchMock)
    render(<App />)

    const statusFilter = await screen.findByRole('combobox', {
      name: 'Verification status',
    })
    await screen.findByRole('button', { name: 'Open incident 50' })

    fireEvent.change(statusFilter, { target: { value: 'passed' } })
    fireEvent.click(screen.getByRole('button', { name: 'Load more incidents' }))

    await waitFor(() => {
      expect(screen.getByRole('button', { name: 'Open incident 51' })).toBeTruthy()
    })

    expect(requestedUrls).toContain('/api/v1/incidents?limit=50&offset=50')
    expect(requestedUrls).not.toContain(
      '/api/v1/incidents?limit=50&offset=50&verification_status=passed',
    )
  })
  it('keeps the latest search results when an older request resolves later', async () => {
    const pendingRequests: Array<{
      resolve: (response: Response) => void
    }> = []

    const fetchMock = vi.fn((input: RequestInfo | URL) => {
      const url = String(input)

      if (url === '/health') {
        return Promise.resolve(jsonResponse({ status: 'ok' }))
      }

      if (url === '/api/v1/auth/me') {
        return Promise.resolve(
          jsonResponse({ authenticated: true, username: 'test-user' }),
        )
      }

      if (url === '/api/v1/incidents?limit=50&offset=0') {
        return Promise.resolve(
          jsonResponse({ items: [], limit: 50, offset: 0 }),
        )
      }

      if (
        url.includes('search=older-search') ||
        url.includes('search=latest-search')
      ) {
        return new Promise<Response>((resolve) => {
          pendingRequests.push({ resolve })
        })
      }

      return Promise.resolve(
        jsonResponse({ detail: `Unexpected request: ${url}` }, 404),
      )
    })

    vi.stubGlobal('fetch', fetchMock)
    render(<App />)

    const searchInput = await screen.findByRole('searchbox', {
      name: 'Search source or logs',
    })

    fireEvent.change(searchInput, { target: { value: 'older-search' } })
    fireEvent.click(screen.getByRole('button', { name: 'Search' }))

    await waitFor(() => {
      expect(pendingRequests).toHaveLength(1)
    })

    fireEvent.change(searchInput, { target: { value: 'latest-search' } })
    fireEvent.click(screen.getByRole('button', { name: 'Search' }))

    await waitFor(() => {
      expect(pendingRequests).toHaveLength(2)
    })

    pendingRequests[1].resolve(
      jsonResponse({
        items: [makeIncident(99, 'passed', 'latest-search result')],
        limit: 50,
        offset: 0,
      }),
    )

    await waitFor(() => {
      expect(
        screen.getByRole('button', { name: 'Open incident 99' }),
      ).toBeTruthy()
    })

    pendingRequests[0].resolve(
      jsonResponse({
        items: [makeIncident(88, 'failed', 'older-search result')],
        limit: 50,
        offset: 0,
      }),
    )

    await waitFor(() => {
      expect(
        screen.getByRole('button', { name: 'Open incident 99' }),
      ).toBeTruthy()
    })

    expect(
      screen.queryByRole('button', { name: 'Open incident 88' }),
    ).toBeNull()
  })
})
