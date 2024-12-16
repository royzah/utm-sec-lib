import * as fs from 'fs';
import * as path from 'path';
import * as dotenv from 'dotenv';
import * as winston from 'winston';
import 'winston-daily-rotate-file';
import { Readable } from 'stream';

interface CustomLevels extends winston.config.AbstractConfigSetLevels {
    fatal: number;
    error: number;
    warn: number;
    info: number;
    debug: number;
}

interface CustomColors extends winston.config.AbstractConfigSetColors {
    fatal: string;
    error: string;
    warn: string;
    info: string;
    debug: string;
}

type CustomLogger = winston.Logger & {
    fatal: winston.LeveledLogMethod;
    error: winston.LeveledLogMethod;
    warn: winston.LeveledLogMethod;
    info: winston.LeveledLogMethod;
    debug: winston.LeveledLogMethod;
};

const LOG_LEVELS: CustomLevels = {
    fatal: 0,
    error: 1,
    warn: 2,
    info: 3,
    debug: 4,
};

const LOG_COLORS: CustomColors = {
    fatal: 'red',
    error: 'red',
    warn: 'yellow',
    info: 'green',
    debug: 'blue',
};

const logger = CreateLogger();

export function CreateLogger(): CustomLogger {
    winston.addColors(LOG_COLORS);

    return winston.createLogger({
        levels: LOG_LEVELS,
        level: 'debug',
        format: winston.format.combine(
            winston.format.colorize({ message: false, level: true }),
            winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
            winston.format.printf(
                (info: winston.Logform.TransformableInfo) =>
                    `${info.timestamp} [${info.level}]: ${info.message}`
            )
        ),
        transports: [
            new winston.transports.Console(),
            new winston.transports.DailyRotateFile({
                filename: 'logs/application-%DATE%.log',
                datePattern: 'YYYY-MM-DD',
                maxFiles: '14d',
            }),
        ],
    }) as CustomLogger;
}

function resolveFilePath(filePath: string): string {
    if (!filePath) {
        logger.error('File path cannot be empty');
        throw new Error('File path cannot be empty');
    }

    if (filePath.startsWith('./')) {
        const relativeFolderPath = filePath.substring(2);
        return path.join(getProjectRootPath(), relativeFolderPath);
    }

    return filePath;
}

export function saveBytesToFile(bytes: Buffer, filePath: string): number {
    try {
        if (!Buffer.isBuffer(bytes)) {
            logger.error('Input must be a Buffer');
            throw new Error('Input must be a Buffer');
        }

        const fullPath = resolveFilePath(filePath);
        fs.writeFileSync(fullPath, bytes);
        return bytes.length;
    } catch (error) {
        const message = `Failed to save bytes to file: ${error}`;
        logger.error(message);
        throw new Error(message);
    }
}

export function getProjectRootPath(): string {
    return path.resolve(__dirname, '../../..');
}

export function loadBytesFromFile(filePath: string): Buffer {
    try {
        const fullPath = resolveFilePath(filePath);
        return fs.readFileSync(fullPath);
    } catch (error) {
        const message = `Failed to load bytes from file: ${error}`;
        logger.error(message);
        throw new Error(message);
    }
}

export function loadEnv(filename: string): void {
    try {
        if (!filename) {
            logger.error('Filename cannot be empty');
            throw new Error('Filename cannot be empty');
        }

        const fullPath = path.join(getProjectRootPath(), filename);
        const result = dotenv.config({ path: fullPath });

        if (result.error) {
            const message = `Error loading ${filename}. Environment files should be placed in the project folder ` +
                '(.env for production, .env.test for testing).';
            logger.error(message);
            throw new Error(message);
        }
    } catch (error) {
        const message = `Failed to load environment variables: ${error}`;
        logger.error(message);
        throw new Error(message);
    }
}

export function getReaderFromJsonString(jsonStr: string): Readable {
    try {
        if (!jsonStr?.trim()) {
            logger.error('JSON string cannot be empty');
            throw new Error('JSON string cannot be empty');
        }

        const jsonObj = JSON.parse(jsonStr);
        const jsonBuffer = Buffer.from(JSON.stringify(jsonObj));

        return new Readable({
            read(): void {
                this.push(jsonBuffer);
                this.push(null);
            },
        });
    } catch (error) {
        const message = error instanceof SyntaxError ?
            'Invalid JSON string' :
            `Failed to create reader from JSON string: ${error}`;
        logger.error(message);
        throw new Error(message);
    }
}