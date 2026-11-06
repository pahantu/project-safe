using System;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text;
using System.Xml;
using System.Threading;
using System.Security.Cryptography;
using System.Collections.Generic;
using System.Text.RegularExpressions;

namespace ProjectSafe {
 public static partial class Vault {
  const int PopularLimit=32*1024*1024;
  // Read-only adapters: undocumented native schemas must never be rewritten on faith.
  static XmlDocument ReadPopularXml(string path) {
   if(new FileInfo(path).Length>PopularLimit)throw new IOException("Проект больше 32 МБ: автоматический разбор пропущен.");
   using(var input=File.OpenRead(path)) {
    int a=input.ReadByte(),b=input.ReadByte();input.Position=0;
    using(var decoded=new MemoryStream()) {
     if(a==0x1f&&b==0x8b) {
      using(var gzip=new GZipStream(input,CompressionMode.Decompress,true))CopyBounded(gzip,decoded);
     }else CopyBounded(input,decoded);
     decoded.Position=0;
     var settings=new XmlReaderSettings{DtdProcessing=DtdProcessing.Prohibit,XmlResolver=null,MaxCharactersInDocument=PopularLimit};
     // Final Cut XML commonly includes a bare DOCTYPE. Ignore declarations but reject
     // any internal subset or external identifier, so no DTD/resource is ever loaded.
     string xml;
     using(var reader=new StreamReader(decoded,Encoding.UTF8,true,4096,true))xml=reader.ReadToEnd();
     if(xml.Contains("<!DOCTYPE")) {
      var bare=new Regex(@"<!DOCTYPE\s+(?:fcpxml|xmeml)\s*>");
      xml=bare.Replace(xml,"");
      if(xml.Contains("<!DOCTYPE"))throw new IOException("DTD с внешними адресами или сущностями не поддерживается.");
     }
     var doc=new XmlDocument{XmlResolver=null,PreserveWhitespace=true};
     using(var text=new StringReader(xml))using(var reader=XmlReader.Create(text,settings))doc.Load(reader);
     return doc;
    }
   }
  }
  static void CopyBounded(Stream input,Stream output) {
   byte[] buffer=new byte[65536];int n;
   while((n=input.Read(buffer,0,buffer.Length))>0) {
    if(output.Length+n>PopularLimit)throw new IOException("Распакованный проект больше 32 МБ: разбор остановлен.");
    output.Write(buffer,0,n);
   }
  }
  static bool IsInterchangeXml(string path) {
   try {var doc=ReadPopularXml(path);return doc.DocumentElement!=null&&new[]{"fcpxml","xmeml","PremiereData","AfterEffectsProject"}.Contains(doc.DocumentElement.LocalName);}catch{return false;}
  }
  static void PopularNotice(Scan scan,Item project,string message) {
   if(!scan.Findings.Any(x=>x.File==project.Relative&&x.Message==message))scan.Findings.Add(new Finding("Проверить",project.Relative,message));
  }
  static void CollectPopularReference(Scan scan,Item project,string value,CancellationToken token) {
   token.ThrowIfCancellationRequested();if(String.IsNullOrWhiteSpace(value))return;
   try {
    string local=value;
    if(local.StartsWith("\\\\",StringComparison.Ordinal)||local.StartsWith("//",StringComparison.Ordinal)) {PopularNotice(scan,project,"Сетевой ресурс не открывается: "+value);return;}
    Uri uri;
    if(Uri.TryCreate(local,UriKind.Absolute,out uri)&&!Path.IsPathRooted(local)) {
     if(!uri.IsFile){PopularNotice(scan,project,"Внешний адрес не загружается: "+value);return;}
     if(!String.IsNullOrEmpty(uri.Host)&&!uri.Host.Equals("localhost",StringComparison.OrdinalIgnoreCase)){PopularNotice(scan,project,"Сетевой ресурс не открывается: "+value);return;}
     local=uri.LocalPath;
    }
    // Windows cannot meaningfully resolve a macOS absolute path against the project.
    if(local.StartsWith("/",StringComparison.Ordinal)&&!local.StartsWith("//",StringComparison.Ordinal)){PopularNotice(scan,project,"Путь с другого компьютера: "+value+". Собери медиа на исходном компьютере или перепривяжи в редакторе.");return;}
    if(local.IndexOfAny(new[]{'*','?'})>=0||Regex.IsMatch(local,@"%0?\d*d|\[\d+-\d+\]")) {PopularNotice(scan,project,"Последовательность изображений требует сбора всей серии в редакторе: "+value);return;}
    string path=Path.GetFullPath(Path.IsPathRooted(local)?local:Path.Combine(Path.GetDirectoryName(project.Source),local));
    NoLinks(path);
    if(!File.Exists(path)) {
     if(!scan.Findings.Any(x=>x.File==project.Relative&&x.Level=="Не найден"&&x.Message==path))scan.Findings.Add(new Finding("Не найден",project.Relative,path));
     return;
    }
    if(!scan.Files.Any(x=>x.Source.Equals(path,StringComparison.OrdinalIgnoreCase))) {
     string id;using(var sha=SHA256.Create())id=BitConverter.ToString(sha.ComputeHash(Encoding.UTF8.GetBytes(path.ToUpperInvariant()))).Replace("-","").Substring(0,16);
     scan.Files.Add(Describe(path,Path.Combine("_linked",id,Path.GetFileName(path)),true));
     scan.Findings.Add(new Finding("Внешний файл",project.Relative,path+" — будет добавлен в _linked."));
    }
   }catch(OperationCanceledException){throw;}
   catch(Exception ex){PopularNotice(scan,project,"Ссылка не собрана: "+value+". "+ex.Message);}
  }
  static void InspectPopular(Scan scan,Item project,CancellationToken token) {
   string editor=Path.GetExtension(project.Source).Equals(".prproj",StringComparison.OrdinalIgnoreCase)?"Premiere Pro":"XML";
   try {
    var doc=ReadPopularXml(project.Source);string root=doc.DocumentElement==null?"":doc.DocumentElement.LocalName;
    string ext=Path.GetExtension(project.Source).ToLowerInvariant();
    if((ext==".prproj"&&root!="PremiereData")||(ext==".aepx"&&root!="AfterEffectsProject")||(ext==".fcpxml"&&root!="fcpxml")||(ext==".psdeps"&&root!="ProjectSafeDependencies"))throw new IOException("Структура не соответствует расширению проекта.");
    XmlNodeList refs;
    if(root=="PremiereData") {
     editor="Premiere Pro";
     refs=doc.SelectNodes("//*[local-name()='ActualMediaFilePath' or local-name()='FilePath' or local-name()='RelativePath' or local-name()='ProxyFilePath']");
     PopularNotice(scan,project,"Premiere Pro: экспериментальный разбор известных XML-полей PRPROJ (включая gzip). Это не полный список зависимостей; Dynamic Link, прокси, LUT, MOGRT и последовательности проверь через Project Manager в Premiere.");
    }else if(root=="AfterEffectsProject") {
     editor="After Effects XML";
     refs=doc.SelectNodes("//*[local-name()='fileReference']/@fullpath");
     PopularNotice(scan,project,"After Effects: собраны доступные fileReference из AEPX. Последовательности изображений, выражения с файлами, шрифты, плагины и ресурсы эффектов требуют Collect Files и проверки в редакторе.");
    }else if(root=="fcpxml") {
     editor="Final Cut / Resolve FCPXML";
     refs=doc.SelectNodes("//*[local-name()='asset' or local-name()='media-rep']/@src");
     PopularNotice(scan,project,"FCPXML: сбор исходных медиа и прокси по asset/media-rep. Это обменный документ, не полная библиотека Final Cut и не замена DRP Resolve. Эффекты, титры и пути macOS требуют исходного редактора.");
    }else if(root=="xmeml") {
     editor="Premiere / Resolve Final Cut XML";
     refs=doc.SelectNodes("//*[local-name()='file']/*[local-name()='pathurl']");
     PopularNotice(scan,project,"Final Cut XML: сбор ссылок pathurl. Экспорт XML может не включать все возможности исходного монтажа; сохраняй нативный проект рядом.");
    }else if(root=="ProjectSafeDependencies"&&doc.DocumentElement.GetAttribute("version")=="1"&&doc.DocumentElement.GetAttribute("editor")=="After Effects") {
     editor="After Effects (выгрузка)";
     refs=doc.SelectNodes("/ProjectSafeDependencies/project/@path | /ProjectSafeDependencies/file/@path");
     foreach(XmlNode warning in doc.SelectNodes("/ProjectSafeDependencies/warning"))PopularNotice(scan,project,warning.InnerText);
     PopularNotice(scan,project,"Выгрузка After Effects — снимок списка файлов на момент экспорта. Повтори её после правок проекта. Прокси собираются, но серии кадров, шрифты, выражения и плагины проверь через Collect Files.");
    }else throw new IOException("Не распознан поддерживаемый обменный документ.");
    int count=0;
    foreach(XmlNode node in refs){CollectPopularReference(scan,project,node.InnerText,token);count++;}
    scan.Findings.Add(new Finding("Сбор связей",project.Relative,editor+": обработано полей путей — "+count+". Оригинал сохранится без изменений; копия Ready не создаётся. После переноса перепривяжи медиа из Project/_linked в редакторе по карте файлов."));
    if(count==0)PopularNotice(scan,project,"Медиа-ссылок не обнаружено. Это не подтверждение полноты проекта.");
   }catch(OperationCanceledException){throw;}
   catch(Exception ex){scan.Findings.Add(new Finding("Формат",project.Relative,editor+": связи не проверены. "+ex.Message+" Оригинал будет сохранён."));}
  }
 }
}
