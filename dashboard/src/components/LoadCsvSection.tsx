import { useState, useCallback, useRef } from 'react';
import type { CsvFileSet } from '../lib/parseCsv';
import clsx from 'clsx';

export type DataSource = 'bundled' | 'uploaded';

type Props = {
  dataSource: DataSource;
  onUseBundled: () => void;
  onUploadComplete: (files: CsvFileSet) => void;
  uploadError: string | null;
  clearUploadError: () => void;
};

function assignFiles(fileList: FileList | null): Partial<Record<keyof CsvFileSet, File>> | null {
  if (!fileList || fileList.length === 0) return null;
  const out: Partial<Record<keyof CsvFileSet, File>> = {};
  for (let i = 0; i < fileList.length; i++) {
    const f = fileList[i];
    const name = f.name.toLowerCase();
    if (name.includes('auth') && name.endsWith('.csv')) out.auth = f;
    else if (name.includes('dns') && name.endsWith('.csv')) out.dns = f;
    else if (name.includes('firewall') && name.endsWith('.csv')) out.firewall = f;
    else if (name.includes('malware') && name.endsWith('.csv')) out.malware = f;
  }
  if (out.auth && out.dns && out.firewall && out.malware) return out as CsvFileSet;
  return null;
}

export function LoadCsvSection({
  dataSource,
  onUseBundled,
  onUploadComplete,
  uploadError,
  clearUploadError,
}: Props) {
  const [dragOver, setDragOver] = useState(false);
  const [fileStatus, setFileStatus] = useState<Record<string, string>>({});
  const authInputRef = useRef<HTMLInputElement>(null);
  const dnsInputRef = useRef<HTMLInputElement>(null);
  const firewallInputRef = useRef<HTMLInputElement>(null);
  const malwareInputRef = useRef<HTMLInputElement>(null);

  const tryApply = useCallback(
    (files: Partial<Record<keyof CsvFileSet, File>> | null) => {
      if (!files || !files.auth || !files.dns || !files.firewall || !files.malware) {
        return false;
      }
      onUploadComplete({
        auth: files.auth,
        dns: files.dns,
        firewall: files.firewall,
        malware: files.malware,
      });
      setFileStatus({
        auth: files.auth.name,
        dns: files.dns.name,
        firewall: files.firewall.name,
        malware: files.malware.name,
      });
      return true;
    },
    [onUploadComplete]
  );

  const handleDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault();
      setDragOver(false);
      clearUploadError();
      const assigned = assignFiles(e.dataTransfer.files);
      if (assigned) tryApply(assigned);
      else if (e.dataTransfer.files.length > 0) {
        // could set an error "Need 4 CSVs: auth, dns, firewall, malware"
      }
    },
    [tryApply, clearUploadError]
  );

  const handleDragOver = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.dataTransfer.dropEffect = 'copy';
    setDragOver(true);
  }, []);

  const handleDragLeave = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setDragOver(false);
  }, []);

  const handleFileInputChange = useCallback(
    (kind: keyof CsvFileSet, file: File | null) => {
      clearUploadError();
      const current: Partial<Record<keyof CsvFileSet, File>> = {
        auth: authInputRef.current?.files?.[0] ?? undefined,
        dns: dnsInputRef.current?.files?.[0] ?? undefined,
        firewall: firewallInputRef.current?.files?.[0] ?? undefined,
        malware: malwareInputRef.current?.files?.[0] ?? undefined,
      };
      if (file) current[kind] = file;
      if (current.auth && current.dns && current.firewall && current.malware) {
        tryApply(current as CsvFileSet);
      }
      setFileStatus((prev) => ({
        ...prev,
        [kind]: file ? file.name : '',
      }));
    },
    [tryApply, clearUploadError]
  );
  const handleSingleInputChange = (kind: keyof CsvFileSet) => (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0] ?? null;
    handleFileInputChange(kind, file);
  };

  return (
    <div className="load-csv">
      <h2 className="load-csv__title">Load CSVs</h2>
      <div className="load-csv__options">
        <button
          type="button"
          className={clsx('load-csv__option', dataSource === 'bundled' && 'load-csv__option--active')}
          onClick={onUseBundled}
        >
          Use sample data
        </button>
        <span className="load-csv__option-sep">or</span>
        <span className={clsx('load-csv__option', dataSource === 'uploaded' && 'load-csv__option--active')}>
          Upload files
        </span>
      </div>

      <div
        className={clsx('load-csv__drop', dragOver && 'load-csv__drop--over')}
        onDrop={handleDrop}
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
      >
        Drop 4 CSVs here (auth, dns, firewall, malware)
      </div>

      <div className="load-csv__inputs">
        {(['auth', 'dns', 'firewall', 'malware'] as const).map((kind) => {
          const inputRef =
            kind === 'auth'
              ? authInputRef
              : kind === 'dns'
                ? dnsInputRef
                : kind === 'firewall'
                  ? firewallInputRef
                  : malwareInputRef;
          return (
            <div key={kind} className="load-csv__input-row">
              <span className="load-csv__input-label">
                {kind === 'auth' && 'Auth'}
                {kind === 'dns' && 'DNS'}
                {kind === 'firewall' && 'Firewall'}
                {kind === 'malware' && 'Malware'}
              </span>
              <input
                ref={inputRef}
                type="file"
                accept=".csv"
                onChange={handleSingleInputChange(kind)}
                className="load-csv__input"
                aria-label={`Choose ${kind} CSV`}
              />
              <button
                type="button"
                className="load-csv__choose-btn"
                onClick={() => inputRef.current?.click()}
              >
                Choose file
              </button>
              <span className="load-csv__input-name" title={fileStatus[kind] ?? ''}>
                {fileStatus[kind] ?? 'No file chosen'}
              </span>
            </div>
          );
        })}
      </div>

      {uploadError && (
        <p className="load-csv__error" role="alert">
          {uploadError}
        </p>
      )}
    </div>
  );
}
